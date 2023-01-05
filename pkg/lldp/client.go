//go:build client
// +build client

package lldp

import (
	"context"
	"fmt"
	"io"
	"net"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"go.uber.org/zap"
)

// Client consumes lldp messages.
type Client struct {
	interfaceName string
	iface         net.Interface
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
		iface:         iface,
		ctx:           ctx,
	}
}

// Start searches on the configured interface for lldp packages and
// pushes the optional TLV SysName and SysDescription fields of each
// found lldp package into the given channel.
func (l *Client) Start(log *zap.SugaredLogger, resultChan chan<- DiscoveryResult) error {
	defer func() {
		log.Warnw("terminating lldp discovery for interface", "interface", l.interfaceName)
		close(resultChan)
		l.Close()
	}()

	var packetSource *gopacket.PacketSource
	for {
		// Recreate interface handle if not exists
		if l.handle == nil {
			var err error
			l.handle, err = pcap.OpenLive(l.iface.Name, 65536, true, 5*time.Second)
			if err != nil {
				return fmt.Errorf("unable to open interface:%s in promiscuous mode: %w", l.iface.Name, err)
			}

			// filter only lldp packages
			bpfFilter := fmt.Sprintf("ether proto %#x", etherType)
			err = l.handle.SetBPFFilter(bpfFilter)
			if err != nil {
				return fmt.Errorf("unable to filter lldp ethernet traffic %#x on interface:%s %w", etherType, l.iface.Name, err)
			}

			packetSource = gopacket.NewPacketSource(l.handle, l.handle.LinkType())
		}

		select {
		default:
			for {
				packet, err := packetSource.NextPacket()
				if err == io.EOF {
					l.handle.Close()
					l.handle = nil
					break
				} else if err != nil {
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
