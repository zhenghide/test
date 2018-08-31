/*
  Name: log.go
  Copyright (c) 2017 Aerospace Information. Co., Ltd.
  Author: heli
  Date: 2017-08-09
  Description:
*/

package log

import (
	"fmt"
	"os"

	"github.com/op/go-logging"
)

var Log = logging.MustGetLogger("log")

const (
	defaultFormat = "%{color}%{time:2006-01-02 15:04:05.000 MST} %{shortfunc} -> %{level:.4s} %{id:03x}%{color:reset} %{message}"
	defaultLevel  = logging.INFO
)

func Init(level string, format string) {
	var logLevel logging.Level
	if level == "" {
		logLevel = defaultLevel
	} else {
		var err error
		logLevel, err = logging.LogLevel(level)
		if err != nil {
			fmt.Printf("Invalid logging level '%s' - ignored", level)
			logLevel = defaultLevel
		}
	}

	if format == "" {
		format = defaultFormat
	}
	formatter := logging.MustStringFormatter(format)

	backend1 := logging.NewLogBackend(os.Stdout, "", 0)
	backend1Formatter := logging.NewBackendFormatter(backend1, formatter)

	//添加数据库backend，把日志写入数据库

	logging.SetBackend(backend1Formatter).SetLevel(logLevel, "")
}
