// Copyright (C) 2015 Eiichiro Watanabe
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//    http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
// implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package main

import (
	"fmt"
	"os"
	"os/signal"
	"runtime"
	"syscall"

	log "github.com/Sirupsen/logrus"
	"github.com/jessevdk/go-flags"
)

var commandOpts struct {
	Debug    bool `short:"d" long:"debug" default:"false" description:"Show verbose debug information"`
	Interval int  `short:"i" long:"interval" default:"5" description:"Specify interval(1-59 min) for reloading pseudo ROA table"`
	Port     int  `short:"p" long:"port" default:"323" description:"Specify listen port for RTR"`
}

func checkError(err error) {
	if err != nil {
		defer log.Infof("Daemon stopped")
		log.Panicf("%v", err)
	}
}

func run(port int, interval int, rsrc *resource) {
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGHUP, syscall.SIGINT, syscall.SIGTERM, syscall.SIGKILL)

	// Prepare RTR server
	rtrServer := newRTRServer(port)
	go rtrServer.run()
	log.Infof("Daemon started")

	// cron for managing time
	alarmCh := make(chan bool)
	cronSpec := fmt.Sprintf("0 */%d * * * *", interval)
	go timeKeeper(alarmCh, cronSpec)

	for {
		select {
		case conn := <-rtrServer.connCh:
			log.Infof("Accepted a new connection from %v", conn.remoteAddr)
			go handleRTR(conn, rsrc)
		case <-alarmCh:
			log.Infof("Alarm triggered")
			rsrc.reload()
		case sig := <-sigCh:
			{
				switch sig {
				case syscall.SIGHUP:
					log.Infof("SIGHUP received")
					rsrc.reload()
				case syscall.SIGINT, syscall.SIGTERM, syscall.SIGKILL:
					return
				}
			}
		}
	}
}

func main() {
	runtime.GOMAXPROCS(runtime.NumCPU())

	// Parse options
	parser := flags.NewParser(&commandOpts, flags.Default)
	parser.Usage = "[OPTIONS] [RPSLFILES]..."
	args, err := parser.Parse()
	if err != nil {
		os.Exit(1)
	}

	log.SetFormatter(&log.TextFormatter{
		FullTimestamp:   true,
		TimestampFormat: "2006/01/02 15:04:05",
	})
	log.SetLevel(log.InfoLevel)
	if commandOpts.Debug {
		log.SetLevel(log.DebugLevel)
	}

	var interval int
	if commandOpts.Interval >= 1 && commandOpts.Interval <= 59 {
		interval = commandOpts.Interval
	} else {
		os.Exit(1)
	}

	// Load IRR data
	rsrc, err := newResource(args)
	checkError(err)

	run(commandOpts.Port, interval, rsrc)
	log.Infof("Daemon stopped")
}
