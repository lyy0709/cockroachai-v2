package utils

import (
	"github.com/gogf/gf/v2/net/ghttp"
	"github.com/gogf/gf/v2/text/gstr"
	"strings"
)

func GetInfo(r *ghttp.Request) (string, string) {
	scheme := "http"
	if r.Request.Header.Get("X-Forwarded-Proto") != "" {
		scheme = r.Request.Header.Get("X-Forwarded-Proto")
	}
	if r.Request.Header.Get("cf-visitor") != "" {
		cfVisitor := r.Request.Header.Get("cf-visitor")
		cfVisitorArr := gstr.Split(cfVisitor, ";")
		for _, v := range cfVisitorArr {
			if strings.Contains(v, "scheme=https") {
				scheme = "https"
			}
		}
	}
	host := r.Request.Host
	return scheme, host
}