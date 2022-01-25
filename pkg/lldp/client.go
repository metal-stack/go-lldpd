package lldp

import (
	"fmt"
	"net"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

// Client consumes lldp messages.
type Client struct {
	Source *gopacket.PacketSource
	Handle *pcap.Handle
}

// DiscoveryResult holds optional TLV SysName and SysDescription fields of a real lldp frame.
type DiscoveryResult struct {
	SysName        string
	SysDescription string
}

// NewClient creates a new lldp client.
func NewClient(iface net.Interface) (*Client, error) {
	handle, err := pcap.OpenLive(iface.Name, 65536, true, 5*time.Second)
	if err != nil {
		return nil, fmt.Errorf("unable to open interface:%s in promiscuous mode: %w", iface.Name, err)
	}

	// filter only lldp packages
	bpfFilter := fmt.Sprintf("ether proto %#x", etherType)
	err = handle.SetBPFFilter(bpfFilter)
	if err != nil {
		return nil, fmt.Errorf("unable to filter lldp ethernet traffic %#x on interface:%s %w", etherType, iface.Name, err)
	}

	src := gopacket.NewPacketSource(handle, handle.LinkType())
	return &Client{
		Source: src,
		Handle: handle,
	}, nil
}

// Start searches on the configured interface for lldp packages and
// pushes the optional TLV SysName and SysDescription fields of each
// found lldp package into the given channel.
func (l *Client) Start(discoveryResult chan<- DiscoveryResult) {
	defer func() {
		close(discoveryResult)
		l.Close()
	}()

	for {
		for packet := range l.Source.Packets() {
			if packet.LinkLayer().LayerType() != layers.LayerTypeEthernet {
				continue
			}
			dr := DiscoveryResult{}
			for _, layer := range packet.Layers() {
				if layer.LayerType() != layers.LayerTypeLinkLayerDiscoveryInfo {
					continue
				}
				info := layer.(*layers.LinkLayerDiscoveryInfo)
				dr.SysName = info.SysName
				dr.SysDescription = info.SysDescription
				discoveryResult <- dr
			}
		}
	}
}

// Close the LLDP client
func (l *Client) Close() {
	l.Handle.Close()
}
