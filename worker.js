// =========================================================================================
// Xlink 21.7 v14 (WASM Enhanced Edition - IPv6 Hotfix)
// =========================================================================================
import { connect } from "cloudflare:sockets";
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
	MAX_BUFFER_SIZE: 8 * 1024 * 1024,
	MAX_EMPTY_READS: 100,
};

let wasmInitialized = false;
import "./wasm_exec.js";

async function initWasm() {
	if (wasmInitialized) return;
	const go = new Go();
	const instance = await WebAssembly.instantiate(wasmCode, go.importObject);
	go.run(instance);
	wasmInitialized = true;
}

// =========================================================================================
// Entry
// =========================================================================================

export default {
	async fetch(request, env, ctx) {
		try {
			await initWasm();
		} catch (e) {
			console.error("WASM Initialization Failed:", e);
			return new Response("WASM failed to load", { status: 500 });
		}

		const token = env.TOKEN || SERVER_CONFIG.DEFAULT_TOKEN;
		const url = new URL(request.url);
		const providedToken = request.headers.get("X-Auth-Token") || url.searchParams.get("token") || "";

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

		const session = handleSession(server, env);
		ctx?.waitUntil?.(session);

		return new Response(null, { status: 101, webSocket: client });
	},
};

// =========================================================================================
// Session Handler
// =========================================================================================

async function handleSession(webSocket, env) {
	const { readable: wsReadable, writable: wsWritable } = websocketToStreams(webSocket);
	const reader = wsReadable.getReader();
	let remoteSocket = null;

	try {
		let accumulatedBuffer = new Uint8Array(0);
		let parsed = null;
		let readCount = 0;
		const MAX_READ_COUNT = 10;

		while (readCount < MAX_READ_COUNT) {
			const { value: chunk, done } = await reader.read();
			if (done) return;
			
			const newBuf = new Uint8Array(accumulatedBuffer.length + chunk.length);
			newBuf.set(accumulatedBuffer);
			newBuf.set(chunk, accumulatedBuffer.length);
			accumulatedBuffer = newBuf;

			parsed = globalThis.wasmParseHeader(accumulatedBuffer);

			if (parsed && parsed.status === "success") break;
			if (parsed && parsed.status === "error") return;
			readCount++;
		}
		
		if (!parsed || parsed.status !== "success") return;

		const host = parsed.host;
		const port = parsed.port;
		const finalS5 = parsed.s5 || (env.SOCKS5_SERVER || SERVER_CONFIG.SERVER_SOCKS5);
		const finalFB = parsed.fb || (env.FALLBACK_SERVER || SERVER_CONFIG.DEFAULT_FALLBACK);
		const initialPayload = accumulatedBuffer.slice(parsed.offset);

		const strategies = [
			{ name: "SOCKS5", enabled: !!finalS5, factory: () => createS5Socket(finalS5, host, port, CONNECT_CONFIG.SOCKS5_TIMEOUT) },
			{ name: "Direct", enabled: true, factory: () => tryConnect({ hostname: host, port }, CONNECT_CONFIG.DIRECT_TIMEOUT) },
			{ name: "Fallback", enabled: !!finalFB, factory: () => {
				const [fh, fp] = parseHostPort(finalFB, 443);
				return tryConnect({ hostname: fh, port: fp }, CONNECT_CONFIG.FALLBACK_TIMEOUT);
			}},
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

		const writer = remoteSocket.writable.getWriter();
		if (initialPayload.length > 0) {
			await writer.write(initialPayload);
		}
		writer.releaseLock();

		const remainderStream = new TransformStream();
		const remainderWriter = remainderStream.writable.getWriter();
		(async () => {
			try {
				while(true) {
					const { value, done } = await reader.read();
					if (done) break;
					await remainderWriter.write(value);
				}
			} catch {}
			finally {
				try { remainderWriter.close(); } catch {}
				try { reader.releaseLock(); } catch {}
			}
		})();
		
		await bidirectionalPipe(remainderStream.readable, wsWritable, remoteSocket);

	} catch (err) {
		console.error("[session]", err?.stack || err);
	} finally {
		safeClose(remoteSocket);
		safeClose(webSocket);
	}
}


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

	const pipe1 = wsReadable.pipeTo(remoteSocket.writable, pipeOptions).catch(() => {});
	const pipe2 = remoteSocket.readable.pipeTo(wsWritable, pipeOptions).catch(() => {});
	
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
		start(controller) {
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
			ws.addEventListener("error", (e) => {
				streamDone = true;
				streamError = new Error("WebSocket error");
				wake();
			});
		},

		pull(controller) {
			return new Promise((resolve) => {
				if (streamCancelled) {
					resolve();
					return;
				}
				if (buffer.length > 0) {
					const chunk = buffer.shift();
					bufferSize -= chunk.length;
					controller.enqueue(chunk);
					resolve();
					return;
				}
				if (streamDone) {
					if (streamError) controller.error(streamError);
					else controller.close();
					resolve();
					return;
				}
				pullResolve = resolve;
			});
		},

		cancel() {
			streamCancelled = true;
			streamDone = true;
			buffer.length = 0;
			bufferSize = 0;
			wake();
			if (ws.readyState === 1) {
				try { ws.close(); } catch {}
			}
		},
	});

	return { readable, writable };
}

// =========================================================================================
// Utilities
// =========================================================================================

// 🔥 终极修复：引入能正确处理 IPv6 地址的 parseHostPort
function parseHostPort(s, defaultPort) {
    if (!s || typeof s !== 'string') return ['', defaultPort];

    // Case 1: IPv6 with port, e.g., "[2001:db8::1]:8080"
    const ipv6WithPortMatch = s.match(/^\[(.+)\]:(\d+)$/);
    if (ipv6WithPortMatch) {
        const port = parseInt(ipv6WithPortMatch[2], 10);
        if (isValidPort(port)) {
            return [ipv6WithPortMatch[1], port];
        }
        return [ipv6WithPortMatch[1], defaultPort];
    }

    // Case 2: IPv6 without port, e.g., "[2001:db8::1]" or "2001:db8::1"
    // This is the key fix: if it contains colons, it's likely an IPv6 address.
    if (s.includes(':')) {
        // If it's wrapped in brackets, remove them.
        const host = s.startsWith('[') && s.endsWith(']') ? s.slice(1, -1) : s;
        // Assume no port is provided for a raw IPv6 address.
        return [host, defaultPort];
    }
    
    // Case 3: IPv4 or domain name with port, e.g., "1.2.3.4:8080" or "google.com:443"
    const lastColon = s.lastIndexOf(":");
    if (lastColon === -1) {
        return [s, defaultPort]; // No port found
    }

    const host = s.slice(0, lastColon);
    const portStr = s.slice(lastColon + 1);
    
    // If what's before the last colon also has a colon, it was an IPv6 address all along.
    if (host.includes(':')) {
        return [s, defaultPort];
    }

    const port = parseInt(portStr, 10);
    if (!isValidPort(port)) {
        return [s, defaultPort]; // Invalid port, return original string
    }

    return [host, port];
}


function isValidPort(port) {
	return Number.isInteger(port) && port >= 1 && port <= 65535;
}

function safeClose(obj) {
	try { obj?.close?.(); } catch {}
}

async function tryConnect(options, timeout) {
	const socket = connect(options);
	let timer;
	try {
		const conn = await Promise.race([
			socket.opened.then(() => socket),
			new Promise((_, reject) => {
				timer = setTimeout(() => reject(new Error("Connect timeout")), timeout);
			}),
		]);
		clearTimeout(timer);
		return conn;
	} catch (e) {
		clearTimeout(timer);
		safeClose(socket);
		throw e;
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
		if (s5param?.includes("@")) {
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
					throw new Error("SOCKS5 read stalled");
				}
			}
			const result = buf.subarray(0, n);
			buf = buf.subarray(n);
			return result;
		}

		await writer.write(user ? Uint8Array.from([5, 1, 2]) : Uint8Array.from([5, 1, 0]));
		const methodResp = await readN(2);
		if (methodResp[0] !== 5 || methodResp[1] === 0xff) throw new Error("SOCKS5 unsupported method");

		if (methodResp[1] === 2) {
			if (!user) throw new Error("SOCKS5 auth required");
			const ub = new TextEncoder().encode(user), pb = new TextEncoder().encode(pass || "");
			const authReq = new Uint8Array(2 + ub.length + 1 + pb.length);
			authReq[0] = 1; authReq[1] = ub.length;
			authReq.set(ub, 2);
			authReq[2 + ub.length] = pb.length;
			authReq.set(pb, 3 + ub.length);
			await writer.write(authReq);
			const authResp = await readN(2);
			if (authResp[1] !== 0) throw new Error("SOCKS5 auth failed");
		}
		
		const isIPv4 = (h) => /^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$/.test(h);
		let addrBytes, addrType;
		if (isIPv4(targetHost)) {
			addrBytes = Uint8Array.from(targetHost.split(".").map(Number));
			addrType = 1;
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
			case 1: await readN(4 + 2); break;
			case 3: { const lb = await readN(1); await readN(lb[0] + 2); break; }
			case 4: await readN(16 + 2); break;
			default: throw new Error(`SOCKS5 unknown ATYP: ${hdr[3]}`);
		}
		
		writer.releaseLock();
		
		if (buf.length > 0) {
			const remainder = buf;
			return {
				opened: Promise.resolve(),
				readable: new ReadableStream({
					start(controller) { controller.enqueue(remainder); },
					pull(controller) { return reader.read().then(({value,done}) => {
						if(done) controller.close(); else controller.enqueue(value);
					});},
					cancel() { return reader.cancel(); }
				}),
				writable: socket.writable,
				close: () => safeClose(socket),
			};
		}
		
		reader.releaseLock();
		return socket;
	})();

	return await Promise.race([
		connectPromise,
		new Promise((_, reject) => {
			timer = setTimeout(() => reject(new Error("SOCKS5 timeout")), timeout);
		}),
	]).finally(() => {
		clearTimeout(timer);
	});
}
