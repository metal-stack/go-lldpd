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

	"log/slog"

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
	portIDSubtype     PortIDSubtype
	lldpMessage       []byte
	socket            int
	log               *slog.Logger
}

// PortIDSubtype selects the port ID TLV subtype (IEEE 802.1AB 8.5.3.2).
type PortIDSubtype uint8

const (
	// PortIDSubtypeInterfaceName sends the interface name (subtype 5), the default.
	PortIDSubtypeInterfaceName PortIDSubtype = PortIDSubtype(lldp.PortIDSubtypeInterfaceName)
	// PortIDSubtypeMACAddress sends the interface's MAC address (subtype 3).
	PortIDSubtypeMACAddress PortIDSubtype = PortIDSubtype(lldp.PortIDSubtypeMACAddress)
	// PortIDSubtypeLocal sends the interface name as locally assigned port ID
	// (subtype 7), as switch LLDP agents announce it for metal-hammer.
	PortIDSubtypeLocal PortIDSubtype = PortIDSubtype(lldp.PortIDSubtypeLocallyAssigned)
)

// Option configures a Daemon.
type Option func(*Daemon)

// WithPortIDSubtype sets the port ID subtype. metal-hammer only accepts
// switch neighbors whose port ID is a MAC address or locally assigned.
func WithPortIDSubtype(s PortIDSubtype) Option {
	return func(d *Daemon) { d.portIDSubtype = s }
}

// NewDaemon create a new LLDPD instance for the given interface
func NewDaemon(log *slog.Logger, systemName, systemDescription, interfaceName string, interval time.Duration, opts ...Option) (*Daemon, error) {
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
		portIDSubtype:     PortIDSubtypeInterfaceName,
		log:               log,
	}
	for _, opt := range opts {
		opt(l)
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
	l.log.Info("lldpd", "interface", l.ifi.Name, "interval", l.interval.String())
}

// create LLDPMessage as byte array
func createLLDPMessage(lldpd *Daemon) ([]byte, error) {
	lf := lldp.Frame{
		ChassisID: &lldp.ChassisID{
			Subtype: lldp.ChassisIDSubtypeMACAddress,
			ID:      []byte(lldpd.ifi.HardwareAddr),
		},
		PortID: portID(lldpd),
		TTL:    2 * lldpd.interval,
		Optional: []*lldp.TLV{
			{
				Type:   lldp.TLVTypePortDescription,
				Value:  []byte(lldpd.ifi.Name),
				Length: uint16(len(lldpd.ifi.Name)), // nolint:gosec
			},
			{
				Type:   lldp.TLVTypeSystemName,
				Value:  []byte(lldpd.systemName),
				Length: uint16(len(lldpd.systemName)), // nolint:gosec
			},
			{
				Type:   lldp.TLVTypeSystemDescription,
				Value:  []byte(lldpd.systemDescription),
				Length: uint16(len(lldpd.systemDescription)), // nolint:gosec
			},
		},
	}
	return lf.MarshalBinary()
}

// portID returns the port ID TLV for the daemon's subtype.
func portID(lldpd *Daemon) *lldp.PortID {
	switch lldpd.portIDSubtype {
	case PortIDSubtypeMACAddress:
		return &lldp.PortID{Subtype: lldp.PortIDSubtypeMACAddress, ID: []byte(lldpd.ifi.HardwareAddr)}
	case PortIDSubtypeLocal:
		return &lldp.PortID{Subtype: lldp.PortIDSubtypeLocallyAssigned, ID: []byte(lldpd.ifi.Name)}
	default:
		return &lldp.PortID{Subtype: lldp.PortIDSubtypeInterfaceName, ID: []byte(lldpd.ifi.Name)}
	}
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
		l.log.Error("lldpd", "failed to marshal ethernet frame", err)
	}

	// Send message forever.
	t := time.NewTicker(l.interval)
	for range t.C {
		if err := l.writeTo(b); err != nil {
			l.log.Error("lldpd", "failed to send message", err)
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
		Halen:    uint8(len(address)), // nolint:gosec
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
