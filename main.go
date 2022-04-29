/*
MIT License

Copyright (c) 2020 The metal-stack Authors.

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
*/

// go-lldpd acts as a send only lldp daemon which is installed on every bare metal machine
// to send required information to the networking backplane like uuid of the machine
// and installation timestamp
package main

import (
	"fmt"
	"os"
	"path"
	"path/filepath"
	"syscall"
	"time"

	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
	"gopkg.in/yaml.v2"

	"github.com/metal-stack/go-lldpd/pkg/lldp"
	"github.com/metal-stack/v"
	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
)

type installerConfig struct {
	// MachineUUID is the unique UUID for this machine, usually the board serial.
	MachineUUID string `yaml:"machineuuid"`
	// Timestamp is the the timestamp of installer config creation.
	Timestamp string `yaml:"timestamp"`
}

const (
	debugFs     = "/sys/kernel/debug"
	installYaml = "/etc/metal/install.yaml"
)

// Starts lldp on every ethernet nic that is up
func main() {
	log := initLog(true)
	log.Infow("lldpd", "version", v.V)
	b, err := os.ReadFile(installYaml)
	if err != nil {
		log.Errorw("lldpd", "unable to open config", err)
		os.Exit(1)
	}
	i := &installerConfig{}
	err = yaml.Unmarshal(b, &i)
	if err != nil {
		log.Errorw("lldpd", "unable to parse config", err)
		os.Exit(1)
	}

	stopFirmwareLLDP(log)

	var interfaces []string
	links, _ := netlink.LinkList()
	for _, nic := range links {
		if nic.Type() == "device" && nic.Attrs().EncapType == "ether" {
			name := nic.Attrs().Name
			if nic.Attrs().OperState == netlink.OperUp {
				interfaces = append(interfaces, name)
			} else {
				log.Infow("interface is not up, will ignore it", "interface", name)
			}
		}
	}

	if len(interfaces) < 2 {
		log.Infow("exiting, because not enough interfaces are up - we need at least two")
		return
	}
	log.Infow("will start lldp on interfaces", "interfaces", interfaces)

	desc := fmt.Sprintf("provisioned since %s", i.Timestamp)
	for _, iface := range interfaces {
		lldpd, err := lldp.NewDaemon(log, i.MachineUUID, desc, iface, 2*time.Second)
		if err != nil {
			log.Errorw("could not start lldp for interface", "interface", iface)
			os.Exit(-1)
		}
		lldpd.Start()
	}
	select {}
}

func unmountDebugFs(log *zap.SugaredLogger) {
	log.Infow("unmounting debugfs")
	err := syscall.Unmount(debugFs, syscall.MNT_FORCE)
	if err != nil {
		log.Errorw("unable to unmount debugfs", "error", err)
	}
}

// stopFirmwareLLDP stop Firmeware LLDP not persistent over reboots, only during runtime.
// mount -t debugfs none /sys/kernel/debug
// echo lldp stop > /sys/kernel/debug/i40e/0000:01:00.2/command
// where <0000:01:00.2> is the pci address of the ethernet nic, this can be inspected by lspci,
// or a loop over all directories in /sys/kernel/debug/i40e/*/command
func stopFirmwareLLDP(log *zap.SugaredLogger) {
	var stat syscall.Statfs_t
	err := syscall.Statfs(debugFs, &stat)
	if err != nil {
		log.Errorw("could not check whether debugfs is mounted", "error", err)
		return
	}

	if stat.Type != unix.DEBUGFS_MAGIC {
		log.Infow("mounting debugfs")
		err := syscall.Mount("debugfs", debugFs, "debugfs", 0, "")
		if err != nil {
			log.Errorw("mounting debugfs failed", "error", err)
			return
		}
		defer unmountDebugFs(log)
	}

	var buggyIntelNicDriverNames = []string{"i40e"}
	for _, driver := range buggyIntelNicDriverNames {
		debugFSPath := path.Join(debugFs, driver)
		log.Infow("check whether lldp needs to be deactivated", "path", debugFSPath)

		if _, err := os.Stat(debugFSPath); os.IsNotExist(err) {
			log.Infow("nothing to do here, because directory for driver does not exist", "path", debugFSPath)
			continue
		}

		err := filepath.Walk(debugFSPath, func(path string, info os.FileInfo, err error) error {
			if err != nil {
				log.Warnw("opening/reading debugfs failed", "path", path, "error", err)
				return err
			}
			if !info.IsDir() && info.Name() == "command" {
				log.Infow("execute echo lldp stop > ", "path", path)
				stopCommand := []byte("lldp stop")
				err := os.WriteFile(path, stopCommand, os.ModePerm)
				if err != nil {
					log.Errorw("stop lldp > command failed", "path", path, "error", err)
				}
			}
			return nil
		})
		if err != nil {
			log.Errorw("unable to walk through debugfs", "path", debugFSPath, "error", err)
		}
	}
}

func initLog(d bool) *zap.SugaredLogger {
	pe := zap.NewProductionEncoderConfig()
	pe.EncodeLevel = zapcore.LowercaseColorLevelEncoder
	pe.EncodeTime = zapcore.ISO8601TimeEncoder
	consoleEncoder := zapcore.NewConsoleEncoder(pe)

	level := zap.InfoLevel
	if d {
		level = zap.DebugLevel
	}

	core := zapcore.NewTee(
		zapcore.NewCore(consoleEncoder, zapcore.AddSync(os.Stdout), level),
	)

	l := zap.New(core)
	return l.Sugar()
}
