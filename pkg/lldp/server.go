/*
MIT License

Copyright (c) 2020 The Metal-Stack Authors.

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

// Package lldp implements sending lldp packets.
package lldp

import (
	"fmt"
	"net"
	"syscall"
	"time"

	log "github.com/inconshreveable/log15"

	"github.com/mdlayher/ethernet"
	"github.com/mdlayher/lldp"
)

const (
	// Make use of an LLDP EtherType.
	// https://www.iana.org/assignments/ieee-802-numbers/ieee-802-numbers.xhtml
	etherType = 0x88cc

	// TC_PRIO_CONTROL is required to be set as socket option,
	// otherwise newer intel nics will not forward packets from this socket
	// defined here: https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/tree/include/uapi/linux/pkt_sched.h#n26
	TC_PRIO_CONTROL = 7
)

var (
	// See https://en.wikipedia.org/wiki/Link_Layer_Discovery_Protocol#Frame_structure
	// for explanation why this destination mac.
	destinationMac = net.HardwareAddr{0x01, 0x80, 0xc2, 0x00, 0x00, 0x0e}
)

// Daemon is a lldp daemon
type Daemon struct {
	systemName        string
	systemDescription string
	ifi               *net.Interface
	interval          time.Duration
	lldpMessage       []byte
	socket            int
}

// NewDaemon create a new LLDPD instance for the given interface
func NewDaemon(systemName, systemDescription, interfaceName string, interval time.Duration) (*Daemon, error) {
	// Open a raw socket on the specified interface, and configure it to accept
	// traffic with etherecho's EtherType.
	ifi, err := net.InterfaceByName(interfaceName)
	if err != nil {
		return nil, fmt.Errorf("lldpd failed to find interface %q error: %w", interfaceName, err)
	}

	log.Info("lldpd", "listen on", ifi.Name)

	l := &Daemon{
		systemName:        systemName,
		systemDescription: systemDescription,
		ifi:               ifi,
		interval:          interval,
	}
	err = l.bindTo(ethernet.Broadcast)
	if err != nil {
		return nil, fmt.Errorf("lldpd failed to bind to socket: %w", err)
	}

	lldp, err := createLLDPMessage(l)
	if err != nil {
		return nil, fmt.Errorf("lldpd failed to create lldp message: %w", err)
	}
	l.lldpMessage = lldp
	return l, nil
}

// Start spawn a goroutine which sends LLDP PDU's every interval given.
func (l *Daemon) Start() {
	go l.sendMessages()
	log.Info("lldpd", "interface", l.ifi.Name, "interval", l.interval)
}

// create LLDPMessage as byte array
func createLLDPMessage(lldpd *Daemon) ([]byte, error) {
	lf := lldp.Frame{
		ChassisID: &lldp.ChassisID{
			Subtype: lldp.ChassisIDSubtypeMACAddress,
			ID:      []byte(lldpd.ifi.HardwareAddr),
		},
		PortID: &lldp.PortID{
			Subtype: lldp.PortIDSubtypeInterfaceName,
			ID:      []byte(lldpd.ifi.Name),
		},
		TTL: 2 * lldpd.interval,
		Optional: []*lldp.TLV{
			{
				Type:   lldp.TLVTypePortDescription,
				Value:  []byte(lldpd.ifi.Name),
				Length: uint16(len(lldpd.ifi.Name)),
			},
			{
				Type:   lldp.TLVTypeSystemName,
				Value:  []byte(lldpd.systemName),
				Length: uint16(len(lldpd.systemName)),
			},
			{
				Type:   lldp.TLVTypeSystemDescription,
				Value:  []byte(lldpd.systemDescription),
				Length: uint16(len(lldpd.systemDescription)),
			},
		},
	}
	return lf.MarshalBinary()
}

// sendMessages continuously sends a message over a connection at regular intervals,
// sourced from specified hardware address.
func (l *Daemon) sendMessages() {
	// Message is LLDP destination.
	f := &ethernet.Frame{
		Destination: destinationMac,
		Source:      l.ifi.HardwareAddr,
		EtherType:   etherType,
		Payload:     l.lldpMessage,
	}

	b, err := f.MarshalBinary()
	if err != nil {
		log.Error("lldpd", "failed to marshal ethernet frame", err)
	}

	// Send message forever.
	t := time.NewTicker(l.interval)
	for range t.C {
		if err := l.writeTo(b); err != nil {
			log.Error("lldpd", "failed to send message", err)
		}
	}
}

// htons converts a short (uint16) from host-to-network byte order.
// Thanks to mikioh for this neat trick:
// https://github.com/mikioh/-stdyng/blob/master/afpacket.go
func htons(i uint16) uint16 {
	return (i<<8)&0xff00 | i>>8
}

// bindTo the specified address an store the raw socket with appropriate priority in the daemon.
func (l *Daemon) bindTo(address net.HardwareAddr) error {
	fd, err := syscall.Socket(syscall.AF_PACKET, syscall.SOCK_RAW, syscall.ETH_P_ALL)
	if err != nil {
		return fmt.Errorf("error creating raw packet socket:%w", err)

	}
	err = syscall.SetsockoptInt(fd, syscall.SOL_SOCKET, syscall.SO_PRIORITY, TC_PRIO_CONTROL)
	if err != nil {
		return fmt.Errorf("error in setting priority option on socket:%w", err)
	}

	var baddr [8]byte
	copy(baddr[:], address)
	addr := syscall.SockaddrLinklayer{
		Protocol: htons(etherType),
		Ifindex:  l.ifi.Index,
		Halen:    uint8(len(address)),
		Addr:     baddr,
	}

	err = syscall.Bind(fd, &addr)
	if err != nil {
		return fmt.Errorf("error binding to socket:%w", err)
	}
	l.socket = fd
	return nil
}

// writeTo the given byte array to the socket
func (l *Daemon) writeTo(pkt []byte) error {
	if l.socket == 0 {
		return fmt.Errorf("socket is not bound")
	}
	_, err := syscall.Write(l.socket, pkt)
	if err != nil {
		return fmt.Errorf("unable to write to socket:%w", err)
	}
	return nil
}
