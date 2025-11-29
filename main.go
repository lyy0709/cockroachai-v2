package main

import (
	"reverse/config"

	_ "reverse/reverse"

	"github.com/gogf/gf/v2/frame/g"

)

func main() {

	// 启动HTTP服务
	s := g.Server()
	s.SetPort(config.PORT)
	s.Run()
}
