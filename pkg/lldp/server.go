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
	"net"
	"time"

	log "github.com/inconshreveable/log15"
	"github.com/pkg/errors"

	"github.com/mdlayher/ethernet"
	"github.com/mdlayher/lldp"
	"github.com/mdlayher/raw"
)

const (
	// Make use of an LLDP EtherType.
	// https://www.iana.org/assignments/ieee-802-numbers/ieee-802-numbers.xhtml
	etherType = 0x88cc
)

var (
	// See https://en.wikipedia.org/wiki/Link_Layer_Discovery_Protocol#Frame_structure
	// for explanation why this destination mac.
	destinationMac = net.HardwareAddr{0x01, 0x80, 0xc2, 0x00, 0x00, 0x0e}
)

// Daemon is a lldp daemon
type Daemon struct {
	SystemName        string
	SystemDescription string
	Interface         *net.Interface
	PacketConn        net.PacketConn
	Interval          time.Duration
	LLDPMessage       []byte
}

// NewDaemon create a new LLDPD instance for the given interface
func NewDaemon(systemName, systemDescription, interfaceName string, interval time.Duration) (*Daemon, error) {
	// Open a raw socket on the specified interface, and configure it to accept
	// traffic with etherecho's EtherType.
	ifi, err := net.InterfaceByName(interfaceName)
	if err != nil {
		return nil, errors.Wrapf(err, "lldpd failed to find interface %q", interfaceName)
	}

	c, err := raw.ListenPacket(ifi, etherType, nil)
	if err != nil {
		return nil, errors.Wrap(err, "lldpd failed to listen")
	}

	log.Info("lldpd", "listen on", ifi.Name)

	l := &Daemon{
		SystemName:        systemName,
		SystemDescription: systemDescription,
		Interface:         ifi,
		Interval:          interval,
		PacketConn:        c,
	}
	lldp, err := createLLDPMessage(l)
	if err != nil {
		return nil, errors.Wrap(err, "lldpd failed to create lldp message")
	}
	l.LLDPMessage = lldp
	return l, nil
}

// Start spawn a goroutine which sends LLDP PDU's every interval given.
func (l *Daemon) Start() {
	go l.sendMessages()
	log.Info("lldpd", "interface", l.Interface.Name, "interval", l.Interval)
}

func createLLDPMessage(lldpd *Daemon) ([]byte, error) {
	lf := lldp.Frame{
		ChassisID: &lldp.ChassisID{
			Subtype: lldp.ChassisIDSubtypeMACAddress,
			ID:      []byte(lldpd.Interface.HardwareAddr),
		},
		PortID: &lldp.PortID{
			Subtype: lldp.PortIDSubtypeInterfaceName,
			ID:      []byte(lldpd.Interface.Name),
		},
		TTL: 2 * lldpd.Interval,
		Optional: []*lldp.TLV{
			{
				Type:   lldp.TLVTypePortDescription,
				Value:  []byte(lldpd.Interface.Name),
				Length: uint16(len(lldpd.Interface.Name)),
			},
			{
				Type:   lldp.TLVTypeSystemName,
				Value:  []byte(lldpd.SystemName),
				Length: uint16(len(lldpd.SystemName)),
			},
			{
				Type:   lldp.TLVTypeSystemDescription,
				Value:  []byte(lldpd.SystemDescription),
				Length: uint16(len(lldpd.SystemDescription)),
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
		Source:      l.Interface.HardwareAddr,
		EtherType:   etherType,
		Payload:     l.LLDPMessage,
	}

	b, err := f.MarshalBinary()
	if err != nil {
		log.Error("lldpd", "failed to marshal ethernet frame", err)
	}

	// Required by Linux, even though the Ethernet frame has a destination.
	// Unused by BSD.
	addr := &raw.Addr{
		HardwareAddr: ethernet.Broadcast,
	}

	// Send message forever.
	t := time.NewTicker(l.Interval)
	for range t.C {
		if _, err := l.PacketConn.WriteTo(b, addr); err != nil {
			log.Error("lldpd", "failed to send message", err)
		}
	}
}
