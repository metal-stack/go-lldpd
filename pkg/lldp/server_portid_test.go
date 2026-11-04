package lldp

import (
	"net"
	"testing"
	"time"

	"github.com/mdlayher/lldp"
)

func TestPortIDSubtype(t *testing.T) {
	ifi := &net.Interface{Name: "port2", HardwareAddr: net.HardwareAddr{0xaa, 0xc1, 0xab, 0x01, 0x02, 0x03}}
	for _, tc := range []struct {
		opts    []Option
		subtype lldp.PortIDSubtype
		id      string
	}{
		{nil, lldp.PortIDSubtypeInterfaceName, "port2"},
		{[]Option{WithPortIDSubtype(PortIDSubtypeLocal)}, lldp.PortIDSubtypeLocallyAssigned, "port2"},
		{[]Option{WithPortIDSubtype(PortIDSubtypeMACAddress)}, lldp.PortIDSubtypeMACAddress, string(ifi.HardwareAddr)},
	} {
		d := &Daemon{systemName: "leaf01", ifi: ifi, interval: 10 * time.Second, portIDSubtype: PortIDSubtypeInterfaceName}
		for _, o := range tc.opts {
			o(d)
		}
		b, err := createLLDPMessage(d)
		if err != nil {
			t.Fatal(err)
		}
		var f lldp.Frame
		if err := f.UnmarshalBinary(b); err != nil {
			t.Fatal(err)
		}
		if f.PortID.Subtype != tc.subtype || string(f.PortID.ID) != tc.id {
			t.Errorf("port ID %v %q, want %v %q", f.PortID.Subtype, f.PortID.ID, tc.subtype, tc.id)
		}
		if f.ChassisID.Subtype != lldp.ChassisIDSubtypeMACAddress {
			t.Errorf("chassis ID subtype %v, want MAC", f.ChassisID.Subtype)
		}
	}
}
