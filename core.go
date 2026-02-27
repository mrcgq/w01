//go:build js && wasm
package main

import (
	"crypto/hmac"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/binary"
	"syscall/js"
)

// =========================================================================================
// WASM Core v2.0 for Xlink
// [升级] 流式解析器，支持分包/粘包处理
// [升级] 成功解析后返回数据偏移量
// =========================================================================================

// 1. WASM 核心：恒定时间 HMAC 鉴权
func verifyToken(this js.Value, args []js.Value) any {
	if len(args) < 2 {
		return false
	}
	providedToken := []byte(args[0].String())
	secretToken := []byte(args[1].String())

	// 使用 HMAC-SHA256
	mac := hmac.New(sha256.New, []byte("xlink-compare-key"))
	mac.Write(secretToken)
	expectedMAC := mac.Sum(nil)

	mac2 := hmac.New(sha256.New, []byte("xlink-compare-key"))
	mac2.Write(providedToken)
	providedMAC := mac2.Sum(nil)

	// 恒定时间比较，绝对防止时序攻击
	return subtle.ConstantTimeCompare(expectedMAC, providedMAC) == 1
}

// 2. WASM 核心：[增强版] Xlink 二进制协议流式解析器
func parseHeader(this js.Value, args []js.Value) any {
	if len(args) < 1 {
		return js.Null()
	}

	// 从 JS Uint8Array 复制数据到 Go 内存
	jsBuf := args[0]
	length := jsBuf.Get("length").Int()
	chunk := make([]byte, length)
	js.CopyBytesToGo(chunk, jsBuf)

	cursor := 0

	// 尝试读取 hostLen
	if length < cursor+1 {
		return map[string]any{"status": "need_more"}
	}
	hostLen := int(chunk[cursor])
	cursor++

	// 尝试读取 Host
	if length < cursor+hostLen {
		return map[string]any{"status": "need_more"}
	}
	host := string(chunk[cursor : cursor+hostLen])
	cursor += hostLen

	// 尝试读取 Port (BigEndian)
	if length < cursor+2 {
		return map[string]any{"status": "need_more"}
	}
	port := int(binary.BigEndian.Uint16(chunk[cursor : cursor+2]))
	cursor += 2

	// 尝试读取 SOCKS5 参数 (s5Len)
	if length < cursor+1 {
		return map[string]any{"status": "need_more"}
	}
	s5Len := int(chunk[cursor])
	cursor++
	s5Str := ""
	if s5Len > 0 {
		if length < cursor+s5Len {
			return map[string]any{"status": "need_more"}
		}
		s5Str = string(chunk[cursor : cursor+s5Len])
		cursor += s5Len
	}

	// 尝试读取 Fallback 参数 (fbLen)
	if length < cursor+1 {
		return map[string]any{"status": "need_more"}
	}
	fbLen := int(chunk[cursor])
	cursor++
	fbStr := ""
	if fbLen > 0 {
		if length < cursor+fbLen {
			return map[string]any{"status": "need_more"}
		}
		fbStr = string(chunk[cursor : cursor+fbLen])
		cursor += fbLen
	}

	// 成功解析头部，返回所有信息
	// 🔥 核心升级：返回 status 和 offset
	return map[string]any{
		"status": "success",
		"host":   host,
		"port":   port,
		"s5":     s5Str,
		"fb":     fbStr,
		"offset": cursor, // 告诉 JS 业务数据从哪里开始
	}
}

// 辅助函数，用于 Go 向 JS 返回结构化错误
// (当前未使用，但保留用于调试)
func generateError(msg string) any {
	return map[string]any{"status": "error", "message": msg}
}

func main() {
	// 将 Go 函数挂载到 JS 的全局对象上
	js.Global().Set("wasmVerifyToken", js.FuncOf(verifyToken))
	js.Global().Set("wasmParseHeader", js.FuncOf(parseHeader))

	// 保持 WASM 实例运行
	<-make(chan struct{})
}
