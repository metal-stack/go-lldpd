package main

import (
	"slices"
	"testing"

	"github.com/vishvananda/netlink"
)

func TestParseMinInterfaces(t *testing.T) {
	tests := []struct {
		name    string
		args    []string
		env     string
		want    int
		wantErr bool
	}{
		{name: "default is two", want: 2},
		{name: "env lowers the minimum", env: "1", want: 1},
		{name: "flag lowers the minimum", args: []string{"-min-interfaces", "1"}, want: 1},
		{name: "flag wins over env", args: []string{"-min-interfaces=3"}, env: "1", want: 3},
		{name: "env not a number", env: "one", wantErr: true},
		{name: "zero is rejected", args: []string{"-min-interfaces=0"}, wantErr: true},
		{name: "negative env is rejected", env: "-1", wantErr: true},
		{name: "unknown flag", args: []string{"-foo"}, wantErr: true},
		{name: "positional argument", args: []string{"eth0"}, wantErr: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			getenv := func(key string) string {
				if key == minInterfacesEnv {
					return tt.env
				}
				return ""
			}
			got, err := parseMinInterfaces(tt.args, getenv)
			if (err != nil) != tt.wantErr {
				t.Fatalf("err = %v, wantErr %v", err, tt.wantErr)
			}
			if !tt.wantErr && got != tt.want {
				t.Errorf("got %d, want %d", got, tt.want)
			}
		})
	}
}

func TestUpEthernetInterfaces(t *testing.T) {
	dev := func(name, encap string, state netlink.LinkOperState) netlink.Link {
		return &netlink.Device{LinkAttrs: netlink.LinkAttrs{Name: name, EncapType: encap, OperState: state}}
	}
	links := []netlink.Link{
		dev("lo", "loopback", netlink.OperUnknown),
		dev("eth0", "ether", netlink.OperUp),
		dev("eth1", "ether", netlink.OperDown),
		dev("eth2", "ether", netlink.OperUp),
		dev("ib0", "infiniband", netlink.OperUp),
		&netlink.Bridge{LinkAttrs: netlink.LinkAttrs{Name: "br0", EncapType: "ether", OperState: netlink.OperUp}},
		&netlink.Veth{LinkAttrs: netlink.LinkAttrs{Name: "veth0", EncapType: "ether", OperState: netlink.OperUp}},
	}
	up, down := upEthernetInterfaces(links)
	if want := []string{"eth0", "eth2"}; !slices.Equal(up, want) {
		t.Errorf("up = %v, want %v", up, want)
	}
	if want := []string{"eth1"}; !slices.Equal(down, want) {
		t.Errorf("down = %v, want %v", down, want)
	}
}
