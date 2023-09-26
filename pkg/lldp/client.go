//go:build client
// +build client

package lldp

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

// Client consumes lldp messages.
type Client struct {
	interfaceName string
	handle        *pcap.Handle
	ctx           context.Context
}

// DiscoveryResult holds optional TLV SysName and SysDescription fields of a real lldp frame.
type DiscoveryResult struct {
	SysName        string
	SysDescription string
}

// NewClient creates a new lldp client.
func NewClient(ctx context.Context, iface net.Interface) *Client {
	return &Client{
		interfaceName: iface.Name,
		ctx:           ctx,
	}
}

// Start searches on the configured interface for lldp packages and
// pushes the optional TLV SysName and SysDescription fields of each
// found lldp package into the given channel.
func (l *Client) Start(log *slog.Logger, resultChan chan<- DiscoveryResult) error {
	defer func() {
		log.Warn("terminating lldp discovery for interface", "interface", l.interfaceName)
		l.Close()
	}()

	var packetSource *gopacket.PacketSource
	for {
		// Recreate interface handle if not exists
		if l.handle == nil {
			var err error
			l.handle, err = pcap.OpenLive(l.interfaceName, 65536, true, 5*time.Second)
			if err != nil {
				return fmt.Errorf("unable to open interface:%s in promiscuous mode: %w", l.interfaceName, err)
			}

			// filter only lldp packages
			bpfFilter := fmt.Sprintf("ether proto %#x", etherType)
			err = l.handle.SetBPFFilter(bpfFilter)
			if err != nil {
				return fmt.Errorf("unable to filter lldp ethernet traffic %#x on interface:%s %w", etherType, l.interfaceName, err)
			}

			packetSource = gopacket.NewPacketSource(l.handle, l.handle.LinkType())
		}

		select {
		case packet, ok := <-packetSource.Packets():
			if !ok {
				l.handle.Close()
				l.handle = nil
				log.Debug("EOF error for the handle")
				continue
			}

			if packet.LinkLayer().LayerType() != layers.LayerTypeEthernet {
				continue
			}
			for _, layer := range packet.Layers() {
				if layer.LayerType() != layers.LayerTypeLinkLayerDiscoveryInfo {
					continue
				}
				info, ok := layer.(*layers.LinkLayerDiscoveryInfo)
				if !ok {
					log.Warn("packet is not LinkLayerDiscoveryInfo", "layer", layer)
					continue
				}
				dr := DiscoveryResult{
					SysName:        info.SysName,
					SysDescription: info.SysDescription,
				}
				// log.Debugw("received LinkLayerDiscoveryInfo", "result", dr)
				resultChan <- dr
			}
		case <-l.ctx.Done():
			log.Debug("context done, terminating lldp discovery")
			return nil
		}
	}
}

// Close the LLDP client
func (l *Client) Close() {
	if l.handle != nil {
		l.handle.Close()
	}
}
