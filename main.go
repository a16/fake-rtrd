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
	"os"
	"os/signal"
	"runtime"
	"syscall"

	"github.com/jessevdk/go-flags"
	log "github.com/sirupsen/logrus"
)

var commandOpts struct {
	Debug     bool `short:"d" long:"debug" description:"Show verbose debug information"`
	UseMaxLen bool `short:"m" long:"maxlen" description:"Use 32 or 128 as MaxLen value, 32 for IPv4, 128 for IPv6. By default(=false), use the same length to the prefix length"`
	Port      int  `short:"p" long:"port" default:"323" description:"Specify listen port for RTR"`
	Quiet     bool `short:"q" long:"quiet" description:"Quiet mode"`
}

func checkError(err error) {
	if err != nil {
		defer log.Infof("Daemon stopped")
		log.Fatalf("%v", err)
	}
}

func mainLoop(mgr *ResourceManager, args []string, port int, debug bool, quiet bool, sigCh chan os.Signal) {
	// Set log level
	if quiet {
		log.SetLevel(log.FatalLevel)
	} else {
		log.SetLevel(log.InfoLevel)
		if debug {
			log.SetLevel(log.DebugLevel)
		}
	}

	// Load IRR data
	err := mgr.Load(args)
	checkError(err)

	// Prepare RTR server
	rtrServer := newRTRServer(port)
	go rtrServer.run()
	log.Infof("Daemon started")
	defer log.Infof("Daemon stopped")

	for {
		select {
		case conn := <-rtrServer.connCh:
			log.Infof("Accepted a new connection from %v", conn.remoteAddr)
			go handleRTR(conn, mgr)
		case sig := <-sigCh:
			{
				switch sig {
				case syscall.SIGHUP:
					log.Infof("SIGHUP received")
					err := mgr.Reload()
					checkError(err)
				case syscall.SIGINT, syscall.SIGTERM, syscall.SIGKILL:
					return
				}
			}
		}
	}
}

func main() {
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGHUP, syscall.SIGINT, syscall.SIGTERM, syscall.SIGKILL)

	runtime.GOMAXPROCS(runtime.NumCPU())

	log.SetFormatter(&log.TextFormatter{
		FullTimestamp:   true,
		TimestampFormat: "2006/01/02 15:04:05",
	})

	// Parse options
	parser := flags.NewParser(&commandOpts, flags.Default)
	parser.Usage = "[OPTIONS] [RPSLFILES]..."
	args, err := parser.Parse()
	if err != nil {
		log.Errorf("%v", err)
		parser.WriteHelp(os.Stdout)
		os.Exit(1)
	}

	mgr := NewResourceManager(commandOpts.UseMaxLen)
	mainLoop(mgr, args, commandOpts.Port, commandOpts.Debug, commandOpts.Quiet, sigCh)
}
