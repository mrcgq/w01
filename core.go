//go:build js && wasm
package main

import (
	"crypto/hmac"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/binary"
	"syscall/js"
)

// 1. WASM 核心：恒定时间 HMAC 鉴权
func verifyToken(this js.Value, args[]js.Value) any {
	if len(args) < 2 {
		return false
	}
	providedToken := []byte(args[0].String())
	secretToken := []byte(args[1].String())

	// 使用 HMAC-SHA256
	mac := hmac.New(sha256.New,[]byte("xlink-compare-key"))
	mac.Write(secretToken)
	expectedMAC := mac.Sum(nil)

	mac2 := hmac.New(sha256.New,[]byte("xlink-compare-key"))
	mac2.Write(providedToken)
	providedMAC := mac2.Sum(nil)

	// 恒定时间比较，绝对防止时序攻击
	return subtle.ConstantTimeCompare(expectedMAC, providedMAC) == 1
}

// 2. WASM 核心：Xlink 二进制协议极速解析器
func parseHeader(this js.Value, args[]js.Value) any {
	if len(args) < 1 {
		return js.Null()
	}

	// 从 JS Uint8Array 复制数据到 Go 内存
	jsBuf := args[0]
	length := jsBuf.Get("length").Int()
	chunk := make([]byte, length)
	js.CopyBytesToGo(chunk, jsBuf)

	cursor := 0

	// 检查 hostLen
	if length < cursor+1 {
		return generateError("missing host length")
	}
	hostLen := int(chunk[cursor])
	cursor++

	// 提取 Host
	if length < cursor+hostLen {
		return generateError("host truncated")
	}
	host := string(chunk[cursor : cursor+hostLen])
	cursor += hostLen

	// 提取 Port (BigEndian)
	if length < cursor+2 {
		return generateError("missing port")
	}
	port := int(binary.BigEndian.Uint16(chunk[cursor : cursor+2]))
	cursor += 2

	// 提取 SOCKS5 参数
	if length < cursor+1 {
		return generateError("missing s5 length")
	}
	s5Len := int(chunk[cursor])
	cursor++
	s5Str := ""
	if s5Len > 0 {
		if length < cursor+s5Len {
			return generateError("s5 truncated")
		}
		s5Str = string(chunk[cursor : cursor+s5Len])
		cursor += s5Len
	}

	// 提取 Fallback 参数
	if length < cursor+1 {
		return generateError("missing fb length")
	}
	fbLen := int(chunk[cursor])
	cursor++
	fbStr := ""
	if fbLen > 0 {
		if length < cursor+fbLen {
			return generateError("fb truncated")
		}
		fbStr = string(chunk[cursor : cursor+fbLen])
		cursor += fbLen
	}

	// 提取剩余的 Initial Payload
	payload := chunk[cursor:]
	jsPayload := js.Global().Get("Uint8Array").New(len(payload))
	js.CopyBytesToJS(jsPayload, payload)

	// 将解析结果组装为 JS 对象返回
	return map[string]any{
		"error":   "",
		"host":    host,
		"port":    port,
		"s5":      s5Str,
		"fb":      fbStr,
		"payload": jsPayload,
	}
}

func generateError(msg string) any {
	return map[string]any{"error": msg}
}

func main() {
	// 将 Go 函数挂载到 JS 的全局对象上
	js.Global().Set("wasmVerifyToken", js.FuncOf(verifyToken))
	js.Global().Set("wasmParseHeader", js.FuncOf(parseHeader))
	
	// 保持 WASM 实例运行
	<-make(chan struct{})
}
