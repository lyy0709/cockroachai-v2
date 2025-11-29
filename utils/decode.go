package utils

import (
	"bytes"
	"io"
	"regexp"
	"strings"

	"golang.org/x/text/encoding"
	"golang.org/x/text/encoding/htmlindex"
	"golang.org/x/text/transform"
)

// DecodeBody 根据Content-Type解码响应体
func DecodeBody(bodyBytes []byte, contentType string) string {
	// 默认使用UTF-8
	charset := "utf-8"

	// 从Content-Type中提取charset
	if contentType != "" {
		re := regexp.MustCompile(`charset=([^;\s]+)`)
		matches := re.FindStringSubmatch(contentType)
		if len(matches) > 1 {
			charset = strings.ToLower(strings.TrimSpace(matches[1]))
		}
	}

	// 如果是UTF-8或者没有指定charset，直接转换
	if charset == "utf-8" || charset == "utf8" || charset == "" {
		return string(bodyBytes)
	}

	// 尝试使用指定的字符集解码
	enc, err := htmlindex.Get(charset)
	if err != nil {
		// 如果无法识别字符集，尝试从HTML内容中检测
		enc = detectCharsetFromHTML(bodyBytes)
		if enc == nil {
			// 最后fallback到UTF-8
			return string(bodyBytes)
		}
	}

	// 解码
	decoder := enc.NewDecoder()
	reader := transform.NewReader(bytes.NewReader(bodyBytes), decoder)
	decoded, err := io.ReadAll(reader)
	if err != nil {
		// 解码失败，返回原始UTF-8字符串
		return string(bodyBytes)
	}

	return string(decoded)
}

// detectCharsetFromHTML 从HTML meta标签中检测字符集
func detectCharsetFromHTML(bodyBytes []byte) encoding.Encoding {
	// 检查HTML meta标签
	content := string(bodyBytes[:min(len(bodyBytes), 2048)]) // 只检查前2KB
	
	// 匹配 <meta charset="xxx">
	re1 := regexp.MustCompile(`<meta[^>]+charset=["']?([^"'\s>]+)`)
	if matches := re1.FindStringSubmatch(content); len(matches) > 1 {
		if enc, err := htmlindex.Get(strings.ToLower(matches[1])); err == nil {
			return enc
		}
	}

	// 匹配 <meta http-equiv="Content-Type" content="text/html; charset=xxx">
	re2 := regexp.MustCompile(`<meta[^>]+content=["']?[^"'>]*charset=([^"'\s;>]+)`)
	if matches := re2.FindStringSubmatch(content); len(matches) > 1 {
		if enc, err := htmlindex.Get(strings.ToLower(matches[1])); err == nil {
			return enc
		}
	}

	return nil
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
