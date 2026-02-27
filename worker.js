

// =========================================================================================
// Xlink 21.7 v14 (WASM Enhanced Edition)
// =========================================================================================
import { connect } from "cloudflare:sockets";
// 导入我们编译好的 WASM 模块 (需配置 Wrangler 识别 wasm 模块)
import wasmCode from "./core.wasm"; 

const SERVER_CONFIG = {
    DEFAULT_FALLBACK: "ProxyIP.US.CMLiussss.net:443",
    SERVER_SOCKS5: "",
    DEFAULT_TOKEN: "my-secret-key-888",
};

const CONNECT_CONFIG = {
    SOCKS5_TIMEOUT: 3000,
    DIRECT_TIMEOUT: 4000,
    FALLBACK_TIMEOUT: 4000,
    MAX_BUFFER_SIZE: 4 * 1024 * 1024,
    MAX_EMPTY_READS: 100,
};

// WASM 实例缓存
let wasmInitialized = false;
import "./wasm_exec.js"; // Go 官方提供的胶水 JS

async function initWasm() {
    if (wasmInitialized) return;
    const go = new Go();
    const instance = await WebAssembly.instantiate(wasmCode, go.importObject);
    go.run(instance); // 启动 Go 运行时，挂载全局函数
    wasmInitialized = true;
}

// =========================================================================================
// Entry
// =========================================================================================

export default {
    async fetch(request, env, ctx) {
        await initWasm(); // 确保 WASM 引擎已启动

        const token = env.TOKEN || SERVER_CONFIG.DEFAULT_TOKEN;
        const url = new URL(request.url);
        const providedToken = request.headers.get("X-Auth-Token") || url.searchParams.get("token") || "";

        // 🔥 升级点 1：调用 WASM 进行亚毫秒级、恒定时间的 HMAC 鉴权
        if (!globalThis.wasmVerifyToken(providedToken, token)) {
            return new Response(null, { status: 403 });
        }

        const upgrade = request.headers.get("Upgrade");
        if (!upgrade || upgrade.toLowerCase() !== "websocket") {
            return new Response(null, { status: 404 });
        }

        const pair = new WebSocketPair();
        const client = pair[0];
        const server = pair[1];
        server.accept();

        const session = handleSession(server);
        ctx?.waitUntil?.(session);

        return new Response(null, { status: 101, webSocket: client });
    },
};

// =========================================================================================
// Session Handler
// =========================================================================================

async function handleSession(webSocket) {
    const { readable: wsReadable, writable: wsWritable } = websocketToStreams(webSocket);
    const reader = wsReadable.getReader();
    let remoteSocket = null;
    let readerReleased = false;

    try {
        const { value: chunk, done } = await reader.read();
        if (done || !chunk) return;

        // 🔥 升级点 2：丢弃恶心的 JS DataView 解析，交由 WASM 瞬间解包
        const parsed = globalThis.wasmParseHeader(chunk);
        
        if (parsed.error) {
            console.warn("[session] WASM parse error:", parsed.error);
            return;
        }

        const host = parsed.host;
        const port = parsed.port;
        const finalS5 = parsed.s5 || SERVER_CONFIG.SERVER_SOCKS5;
        const finalFB = parsed.fb || SERVER_CONFIG.DEFAULT_FALLBACK;
        const initialPayload = parsed.payload;

        // --- 容灾策略连接逻辑保持不变 (完全依赖 CF 的 I/O，JS 处理最优) ---
        const strategies =[
            {
                name: "SOCKS5",
                enabled: !!finalS5,
                factory: () => createS5Socket(finalS5, host, port, CONNECT_CONFIG.SOCKS5_TIMEOUT)
            },
            {
                name: "Direct",
                enabled: true,
                factory: () => tryConnect({ hostname: host, port }, CONNECT_CONFIG.DIRECT_TIMEOUT)
            },
            {
                name: "Fallback",
                enabled: !!finalFB,
                factory: () => {
                    const [fh, fp] = parseHostPort(finalFB, 443);
                    return tryConnect({ hostname: fh, port: fp }, CONNECT_CONFIG.FALLBACK_TIMEOUT);
                }
            },
        ];

        for (const { name, enabled, factory } of strategies) {
            if (!enabled) continue;
            try {
                remoteSocket = await factory();
                if (remoteSocket) break;
            } catch (e) {
                remoteSocket = null;
            }
        }

        if (!remoteSocket) return;

        const remoteWriter = remoteSocket.writable.getWriter();
        if (initialPayload.length > 0) {
            await remoteWriter.write(initialPayload);
        }
        remoteWriter.releaseLock();
        reader.releaseLock();
        readerReleased = true;

        // 🔥 升级点 3：利用 JS 底层的 pipeTo 进行 C++ 级别的零拷贝转发
        await bidirectionalPipe(wsReadable, wsWritable, remoteSocket);

    } catch (err) {
        console.error("[session]", err?.message || err);
    } finally {
        if (!readerReleased) {
            try { reader.releaseLock(); } catch {}
        }
        safeClose(remoteSocket);
        safeClose(webSocket);
    }
}

// ... 下方的 bidirectionalPipe, websocketToStreams, createS5Socket 函数完全保持原样不变 ...
// (因为这些全是流控制和 I/O，JS 是最合适的)


// =========================================================================================
// Bidirectional Pipe
// =========================================================================================

async function bidirectionalPipe(wsReadable, wsWritable, remoteSocket) {
    const ac = new AbortController();
    const { signal } = ac;

    const pipeOptions = {
        signal,
        preventClose: true,
        preventAbort: true,
        preventCancel: true
    };

    const pipe1 = wsReadable
        .pipeTo(remoteSocket.writable, pipeOptions)
        .catch(() => {});
    const pipe2 = remoteSocket.readable
        .pipeTo(wsWritable, pipeOptions)
        .catch(() => {});

    await Promise.race([pipe1, pipe2]);
    ac.abort();
    await Promise.allSettled([pipe1, pipe2]);

    try { await wsReadable.cancel(); } catch {}
    try { await remoteSocket.readable.cancel(); } catch {}
    try { await wsWritable.close(); } catch {}
    try { await remoteSocket.writable.close(); } catch {}
}

// =========================================================================================
// WebSocket <-> Streams (Pull Mode)
// =========================================================================================

function websocketToStreams(ws) {
    const writable = new WritableStream({
        write(chunk) {
            if (ws.readyState !== 1) {
                throw new Error("WebSocket is not open");
            }
            ws.send(chunk);
        },
        close() {
            if (ws.readyState === 1) ws.close(1000);
        },
    });

    const buffer = [];
    let bufferSize = 0;
    let pullResolve = null;
    let streamDone = false;
    let streamError = null;
    let streamCancelled = false;

    function wake() {
        if (pullResolve) {
            const r = pullResolve;
            pullResolve = null;
            r();
        }
    }

    const readable = new ReadableStream({
        start() {
            ws.addEventListener("message", (e) => {
                if (!(e.data instanceof ArrayBuffer)) {
                    console.warn("[ws] received non-binary message, closing");
                    streamError = new Error("Unexpected text frame");
                    streamDone = true;
                    try { ws.close(1003, "Binary only"); } catch {}
                    wake();
                    return;
                }

                const chunk = new Uint8Array(e.data);
                buffer.push(chunk);
                bufferSize += chunk.length;

                if (bufferSize > CONNECT_CONFIG.MAX_BUFFER_SIZE) {
                    streamError = new Error("WebSocket buffer overflow");
                    streamDone = true;
                    try { ws.close(1008, "Buffer overflow"); } catch {}
                }
                wake();
            });
            ws.addEventListener("close", () => {
                streamDone = true;
                wake();
            });
            ws.addEventListener("error", () => {
                streamDone = true;
                streamError = new Error("WebSocket error");
                wake();
            });
        },

        pull(controller) {
            if (buffer.length > 0) {
                const chunk = buffer.shift();
                bufferSize -= chunk.length;
                controller.enqueue(chunk);
                return;
            }
            if (streamDone) {
                return streamError
                    ? controller.error(streamError)
                    : controller.close();
            }
            return new Promise((resolve) => {
                pullResolve = resolve;
            }).then(() => {
                if (streamCancelled) return;
                if (controller.desiredSize === null) return;

                if (buffer.length > 0) {
                    const chunk = buffer.shift();
                    bufferSize -= chunk.length;
                    controller.enqueue(chunk);
                } else if (streamDone) {
                    if (streamError) controller.error(streamError);
                    else controller.close();
                }
            });
        },

        cancel() {
            streamCancelled = true;
            streamDone = true;
            buffer.length = 0;
            bufferSize = 0;
            wake();
            try { ws.close(); } catch {}
        },
    });

    return { readable, writable };
}

// =========================================================================================
// Utilities
// =========================================================================================

function parseHostPort(s, defaultPort) {
    if (!s || typeof s !== "string") return ["", defaultPort];

    const ipv6Match = s.match(/^\[(.+)\]:(\d+)$/);
    if (ipv6Match) {
        const port = parseInt(ipv6Match[2], 10);
        if (isValidPort(port)) return [ipv6Match[1], port];
        return [ipv6Match[1], defaultPort];
    }

    if (s.startsWith("[") && s.endsWith("]")) {
        return [s.slice(1, -1), defaultPort];
    }
    const colonCount = (s.match(/:/g) || []).length;
    if (colonCount > 1) return [s, defaultPort];

    const lastColon = s.lastIndexOf(":");
    if (lastColon === -1) return [s, defaultPort];

    const host = s.slice(0, lastColon);
    const portStr = s.slice(lastColon + 1);
    const port = parseInt(portStr, 10);

    if (!isValidPort(port)) return [s, defaultPort];
    return [host, port];
}

function isValidPort(port) {
    return Number.isInteger(port) && port >= 1 && port <= 65535;
}

function isIPv4(s) {
    const parts = s.split(".");
    if (parts.length !== 4) return false;
    return parts.every((p) => {
        const n = Number(p);
        return Number.isInteger(n) && n >= 0 && n <= 255 && String(n) === p;
    });
}

function safeClose(obj) {
    try { obj?.close?.(); } catch {}
}

async function tryConnect(options, timeout) {
    const socket = connect(options);
    let timer;
    try {
        return await Promise.race([
            socket.opened.then(() => socket),
            new Promise((_, reject) => {
                timer = setTimeout(
                    () => reject(new Error("Connect timeout")),
                    timeout
                );
            }),
        ]);
    } catch (e) {
        safeClose(socket);
        throw e;
    } finally {
        clearTimeout(timer);
    }
}

// =========================================================================================
// SOCKS5 Connector
// =========================================================================================

async function createS5Socket(s5param, targetHost, targetPort, timeout) {
    let socket = null;
    let timer;

    const connectPromise = (async () => {
        let user = null, pass = null, host = s5param;

        // 支持 socks5:// 和 socks:// URL 格式
        if (s5param?.startsWith("socks5://") || s5param?.startsWith("socks://")) {
            try {
                const url = new URL(s5param);
                user = url.username ? decodeURIComponent(url.username) : null;
                pass = url.password ? decodeURIComponent(url.password) : null;
                // 处理 IPv6: url.hostname 会自动去掉方括号
                host = url.hostname.includes(":")
                    ? `[${url.hostname}]:${url.port || 1080}`
                    : `${url.hostname}:${url.port || 1080}`;
            } catch {
                // URL 解析失败，回退到去掉前缀后的原始解析
                host = s5param.replace(/^socks5?:\/\//, "");
                if (host.includes("@")) {
                    const atIdx = host.lastIndexOf("@");
                    const authPart = host.slice(0, atIdx);
                    host = host.slice(atIdx + 1);
                    const colonIdx = authPart.indexOf(":");
                    if (colonIdx !== -1) {
                        user = authPart.slice(0, colonIdx);
                        pass = authPart.slice(colonIdx + 1);
                    } else {
                        user = authPart;
                    }
                }
            }
        } else if (s5param?.includes("@")) {
            // 原有逻辑：user:pass@host:port 格式
            const atIdx = s5param.lastIndexOf("@");
            const authPart = s5param.slice(0, atIdx);
            host = s5param.slice(atIdx + 1);
            const colonIdx = authPart.indexOf(":");
            if (colonIdx !== -1) {
                user = authPart.slice(0, colonIdx);
                pass = authPart.slice(colonIdx + 1);
            } else {
                user = authPart;
            }
        }

        const [proxyHost, proxyPort] = parseHostPort(host, 1080);
        socket = connect({ hostname: proxyHost, port: Number(proxyPort) });
        await socket.opened;

        const writer = socket.writable.getWriter();
        const reader = socket.readable.getReader();
        let buf = new Uint8Array(0);

        async function readN(n) {
            let emptyReads = 0;
            while (buf.length < n) {
                const { value, done } = await reader.read();
                if (done) throw new Error("SOCKS5 connection closed");
                if (value?.length) {
                    emptyReads = 0;
                    const tmp = new Uint8Array(buf.length + value.length);
                    tmp.set(buf);
                    tmp.set(value, buf.length);
                    buf = tmp;
                } else if (++emptyReads > CONNECT_CONFIG.MAX_EMPTY_READS) {
                    throw new Error("SOCKS5 read stalled: too many empty reads");
                }
            }
            const result = buf.subarray(0, n);
            buf = buf.subarray(n);
            return result;
        }

        await writer.write(
            user ? Uint8Array.from([5, 2, 0, 2]) : Uint8Array.from([5, 1, 0])
        );

        const methodResp = await readN(2);
        if (methodResp[0] !== 5 || methodResp[1] === 0xff) {
            throw new Error("SOCKS5 unsupported method");
        }

        if (methodResp[1] === 2) {
            if (!user || pass === null) {
                throw new Error("SOCKS5 auth required but no credentials");
            }
            const ub = new TextEncoder().encode(user);
            const pb = new TextEncoder().encode(pass);
            const authReq = new Uint8Array(3 + ub.length + pb.length);
            authReq[0] = 1;
            authReq[1] = ub.length;
            authReq.set(ub, 2);
            authReq[2 + ub.length] = pb.length;
            authReq.set(pb, 3 + ub.length);
            await writer.write(authReq);

            const authResp = await readN(2);
            if (authResp[1] !== 0) throw new Error("SOCKS5 auth failed");
        }

        let addrBytes, addrType;
        if (isIPv4(targetHost)) {
            addrBytes = Uint8Array.from(targetHost.split(".").map(Number));
            addrType = 1;
        } else if (targetHost.includes(":")) {
            addrBytes = ipv6ToBytes(targetHost);
            addrType = 4;
        } else {
            const db = new TextEncoder().encode(targetHost);
            addrBytes = new Uint8Array([db.length, ...db]);
            addrType = 3;
        }

        const req = new Uint8Array(4 + addrBytes.length + 2);
        req.set([5, 1, 0, addrType], 0);
        req.set(addrBytes, 4);
        new DataView(req.buffer).setUint16(4 + addrBytes.length, targetPort);
        await writer.write(req);

        const hdr = await readN(4);
        if (hdr[1] !== 0) throw new Error(`SOCKS5 connect failed: ${hdr[1]}`);

        switch (hdr[3]) {
            case 1:  await readN(4 + 2);  break;
            case 4:  await readN(16 + 2); break;
            case 3: {
                const lb = await readN(1);
                await readN(lb[0] + 2);
                break;
            }
            default: throw new Error(`SOCKS5 unknown ATYP: ${hdr[3]}`);
        }

        writer.releaseLock();

        if (buf.length > 0) {
            const remainder = buf;
            let remainderSent = false;
            let wrapperClosed = false;

            return {
                opened: Promise.resolve(),
                readable: new ReadableStream({
                    async pull(controller) {
                        if (wrapperClosed) return;

                        if (!remainderSent) {
                            remainderSent = true;
                            controller.enqueue(remainder);
                            return;
                        }

                        try {
                            const { value, done } = await reader.read();
                            if (done) {
                                wrapperClosed = true;
                                try { reader.releaseLock(); } catch {}
                                try { controller.close(); } catch {}
                            } else if (value && value.length > 0) {
                                try { controller.enqueue(value); } catch {}
                            }
                        } catch (e) {
                            wrapperClosed = true;
                            try { reader.releaseLock(); } catch {}
                            try { controller.error(e); } catch {}
                        }
                    },
                    cancel() {
                        wrapperClosed = true;
                        return reader.cancel().finally(() => {
                            try { reader.releaseLock(); } catch {}
                        });
                    },
                }),
                writable: socket.writable,
                close: () => safeClose(socket),
            };
        }

        reader.releaseLock();
        return socket;
    })();

    const timeoutPromise = new Promise((_, reject) => {
        timer = setTimeout(() => {
            safeClose(socket);
            reject(new Error("SOCKS5 timeout"));
        }, timeout);
    });

    try {
        return await Promise.race([connectPromise, timeoutPromise]);
    } catch (err) {
        safeClose(socket);
        throw err;
    } finally {
        clearTimeout(timer);
        connectPromise.catch(() => {});
    }
}

// =========================================================================================
// IPv6 Parser
// =========================================================================================

function ipv6ToBytes(addr) {
    const clean = addr.replace(/^\[|\]$/g, "");

    const ipv4Match = clean.match(/:([\d.]+)$/);
    if (ipv4Match && isIPv4(ipv4Match[1])) {
        const ipv6Part = clean.slice(0, clean.lastIndexOf(":"));
        const ipv6Bytes = parseIpv6Part(ipv6Part, 6);
        const ipv4Parts = ipv4Match[1].split(".").map(Number);
        const bytes = new Uint8Array(16);
        bytes.set(ipv6Bytes.subarray(0, 12), 0);
        bytes.set(ipv4Parts, 12);
        return bytes;
    }

    return parseIpv6Part(clean, 8);
}

function parseIpv6Part(addr, numGroups) {
    const parts = addr.split("::");
    const head = parts[0] ? parts[0].split(":").filter(Boolean) : [];
    const tail = parts[1] ? parts[1].split(":").filter(Boolean) : [];
    const gap = numGroups - head.length - tail.length;
    const full = [...head, ...Array(Math.max(gap, 0)).fill("0"), ...tail];

    const bytes = new Uint8Array(numGroups * 2);
    for (let i = 0; i < numGroups; i++) {
        const val = parseInt(full[i] || "0", 16);
        bytes[i * 2] = (val >> 8) & 0xff;
        bytes[i * 2 + 1] = val & 0xff;
    }
    return bytes;
}
