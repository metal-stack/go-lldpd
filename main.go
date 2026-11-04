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
	"flag"
	"fmt"
	"log/slog"
	"os"
	"path"
	"path/filepath"
	"strconv"
	"syscall"
	"time"

	"gopkg.in/yaml.v3"

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

	// defaultMinInterfaces is the production requirement: every machine is dual-homed to two leaf switches.
	defaultMinInterfaces = 2
	// minInterfacesEnv overrides the default, e.g. from a systemd drop-in in single-switch lab setups.
	minInterfacesEnv = "LLDPD_MIN_INTERFACES"
)

// Starts lldp on every ethernet nic that is up
func main() {
	jsonHandler := slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{})
	log := slog.New(jsonHandler)
	log.Info("lldpd", "version", v.V)
	minInterfaces, err := parseMinInterfaces(os.Args[1:], os.Getenv)
	if err != nil {
		log.Error("lldpd", "invalid arguments", err)
		os.Exit(2)
	}
	b, err := os.ReadFile(installYaml)
	if err != nil {
		log.Error("lldpd", "unable to open config", err)
		os.Exit(1)
	}
	i := &installerConfig{}
	err = yaml.Unmarshal(b, &i)
	if err != nil {
		log.Error("lldpd", "unable to parse config", err)
		os.Exit(1)
	}

	stopFirmwareLLDP(log)

	links, _ := netlink.LinkList()
	interfaces, down := upEthernetInterfaces(links)
	for _, name := range down {
		log.Info("interface is not up, will ignore it", "interface", name)
	}

	if len(interfaces) < minInterfaces {
		log.Info("exiting, because not enough interfaces are up", "up", len(interfaces), "minimum", minInterfaces)
		return
	}
	log.Info("will start lldp on interfaces", "interfaces", interfaces)

	desc := fmt.Sprintf("provisioned since %s", i.Timestamp)
	for _, iface := range interfaces {
		lldpd, err := lldp.NewDaemon(log, i.MachineUUID, desc, iface, 2*time.Second)
		if err != nil {
			log.Error("could not start lldp for interface", "interface", iface)
			os.Exit(-1)
		}
		lldpd.Start()
	}
	select {}
}

// parseMinInterfaces returns the minimum number of interfaces that must be up.
// Precedence: flag -min-interfaces, then environment variable LLDPD_MIN_INTERFACES, then 2.
func parseMinInterfaces(args []string, getenv func(string) string) (int, error) {
	def := defaultMinInterfaces
	if env := getenv(minInterfacesEnv); env != "" {
		n, err := strconv.Atoi(env)
		if err != nil {
			return 0, fmt.Errorf("%s=%q is not a number", minInterfacesEnv, env)
		}
		def = n
	}
	fs := flag.NewFlagSet("lldpd", flag.ContinueOnError)
	n := fs.Int("min-interfaces", def, "minimum number of ethernet interfaces that must be up, otherwise lldpd exits (env "+minInterfacesEnv+")")
	if err := fs.Parse(args); err != nil {
		return 0, err
	}
	if fs.NArg() > 0 {
		return 0, fmt.Errorf("unexpected arguments: %v", fs.Args())
	}
	if *n < 1 {
		return 0, fmt.Errorf("minimum number of interfaces must be at least 1, got %d", *n)
	}
	return *n, nil
}

// upEthernetInterfaces returns the names of physical ethernet devices that are up, and of those that are not.
func upEthernetInterfaces(links []netlink.Link) (up, down []string) {
	for _, nic := range links {
		if nic.Type() != "device" || nic.Attrs().EncapType != "ether" {
			continue
		}
		if nic.Attrs().OperState == netlink.OperUp {
			up = append(up, nic.Attrs().Name)
		} else {
			down = append(down, nic.Attrs().Name)
		}
	}
	return up, down
}

func unmountDebugFs(log *slog.Logger) {
	log.Info("unmounting debugfs")
	err := syscall.Unmount(debugFs, syscall.MNT_FORCE)
	if err != nil {
		log.Error("unable to unmount debugfs", "error", err)
	}
}

// stopFirmwareLLDP stop Firmware LLDP not persistent over reboots, only during runtime.
// mount -t debugfs none /sys/kernel/debug
// echo lldp stop > /sys/kernel/debug/i40e/0000:01:00.2/command
// where <0000:01:00.2> is the pci address of the ethernet nic, this can be inspected by lspci,
// or a loop over all directories in /sys/kernel/debug/i40e/*/command
func stopFirmwareLLDP(log *slog.Logger) {
	var stat syscall.Statfs_t
	err := syscall.Statfs(debugFs, &stat)
	if err != nil {
		log.Error("could not check whether debugfs is mounted", "error", err)
		return
	}

	if stat.Type != unix.DEBUGFS_MAGIC {
		log.Info("mounting debugfs")
		err := syscall.Mount("debugfs", debugFs, "debugfs", 0, "")
		if err != nil {
			log.Error("mounting debugfs failed", "error", err)
			return
		}
		defer unmountDebugFs(log)
	}

	var buggyIntelNicDriverNames = []string{"i40e"}
	for _, driver := range buggyIntelNicDriverNames {
		debugFSPath := path.Join(debugFs, driver)
		log.Info("check whether lldp needs to be deactivated", "path", debugFSPath)

		if _, err := os.Stat(debugFSPath); os.IsNotExist(err) {
			log.Info("nothing to do here, because directory for driver does not exist", "path", debugFSPath)
			continue
		}

		err := filepath.Walk(debugFSPath, func(path string, info os.FileInfo, err error) error {
			if err != nil {
				log.Warn("opening/reading debugfs failed", "path", path, "error", err)
				return err
			}
			if !info.IsDir() && info.Name() == "command" {
				log.Info("execute echo lldp stop > ", "path", path)
				stopCommand := []byte("lldp stop")
				err := os.WriteFile(path, stopCommand, os.ModePerm) // nolint:gosec
				if err != nil {
					log.Error("stop lldp > command failed", "path", path, "error", err)
				}
			}
			return nil
		})
		if err != nil {
			log.Error("unable to walk through debugfs", "path", debugFSPath, "error", err)
		}
	}
}
