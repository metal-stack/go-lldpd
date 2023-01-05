//go:build client
// +build client

package lldp

import (
	"context"
	"fmt"
	"net"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"go.uber.org/zap"
)

// Client consumes lldp messages.
type Client struct {
	source *gopacket.PacketSource
	handle *pcap.Handle
	ctx    context.Context
}

// DiscoveryResult holds optional TLV SysName and SysDescription fields of a real lldp frame.
type DiscoveryResult struct {
	SysName        string
	SysDescription string
}

// NewClient creates a new lldp client.
func NewClient(ctx context.Context, iface net.Interface) (*Client, error) {
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
		source: src,
		handle: handle,
		ctx:    ctx,
	}, nil
}

// Start searches on the configured interface for lldp packages and
// pushes the optional TLV SysName and SysDescription fields of each
// found lldp package into the given channel.
func (l *Client) Start(log *zap.SugaredLogger, resultChan chan<- DiscoveryResult) {
	defer func() {
		close(resultChan)
		l.Close()
	}()

	for {
		select {
		default:
			for packet := range l.source.Packets() {
				if packet.LinkLayer().LayerType() != layers.LayerTypeEthernet {
					continue
				}
				for _, layer := range packet.Layers() {
					if layer.LayerType() != layers.LayerTypeLinkLayerDiscoveryInfo {
						continue
					}
					info, ok := layer.(*layers.LinkLayerDiscoveryInfo)
					if !ok {
						log.Warnw("packet is not LinkLayerDiscoveryInfo", "layer", layer)
						continue
					}
					dr := DiscoveryResult{
						SysName:        info.SysName,
						SysDescription: info.SysDescription,
					}
					log.Debugw("received LinkLayerDiscoveryInfo", "result", dr)
					resultChan <- dr
				}
			}
		case <-l.ctx.Done():
			log.Debugw("context done, terminating lldp discovery")
			return
		}
	}
}

// Close the LLDP client
func (l *Client) Close() {
	l.handle.Close()
}
