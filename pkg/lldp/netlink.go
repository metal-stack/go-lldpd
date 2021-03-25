package lldp

import (
	"net"
	"os"
	"syscall"
	"time"

	"github.com/mdlayher/raw"
	"golang.org/x/net/bpf"
	"golang.org/x/sys/unix"
)

// packetConn is the Linux-specific implementation of net.PacketConn for this
// package.
type packetConn struct {
	ifi *net.Interface
	s   socket
	pbe uint16
}

// WriteTo implements the net.PacketConn.WriteTo method.
func (p *packetConn) WriteTo(b []byte, addr net.Addr) (int, error) {
	// Ensure correct Addr type.
	a, ok := addr.(*raw.Addr)
	if !ok || a.HardwareAddr == nil {
		return 0, unix.EINVAL
	}

	// Convert hardware address back to byte array form.
	var baddr [8]byte
	copy(baddr[:], a.HardwareAddr)

	// Send message on socket to the specified hardware address from addr
	// packet(7):
	//   When you send packets it is enough to specify sll_family, sll_addr,
	//   sll_halen, sll_ifindex, and sll_protocol. The other fields should
	//   be 0.
	// In this case, sll_family is taken care of automatically by unix.
	err := p.s.Sendto(b, 0, &unix.SockaddrNetlink{
		Pid:    0,
		Family: unix.AF_NETLINK,
	})
	return len(b), err
}

// socket is an interface which enables swapping out socket syscalls for
// testing.
type socket interface {
	Bind(unix.Sockaddr) error
	Close() error
	GetSockoptTpacketStats(level, name int) (*unix.TpacketStats, error)
	Recvfrom([]byte, int) (int, unix.Sockaddr, error)
	Sendto([]byte, int, unix.Sockaddr) error
	SetSockoptPacketMreq(level, name int, mreq *unix.PacketMreq) error
	SetSockoptSockFprog(level, name int, fprog *unix.SockFprog) error
	SetDeadline(time.Time) error
	SetReadDeadline(time.Time) error
	SetWriteDeadline(time.Time) error
}

// htons converts a short (uint16) from host-to-network byte order.
// Thanks to mikioh for this neat trick:
// https://github.com/mikioh/-stdyng/blob/master/afpacket.go
func htons(i uint16) uint16 {
	return (i<<8)&0xff00 | i>>8
}

// static int init_socket(void)
// {
// 	int sd;
// 	int rcv_size = MAX_MSG_SIZE;
// 	struct sockaddr_nl snl;
// 	int reuse = 1;

// 	sd = socket(PF_NETLINK, SOCK_RAW, NETLINK_ROUTE);
// 	if (sd < 0)
// 		return sd;

// 	if (setsockopt(sd, SOL_SOCKET, SO_RCVBUF, &rcv_size, sizeof(int)) < 0) {
// 		close(sd);
// 		return -EIO;
// 	}

// 	if (setsockopt(sd, SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof(int)) < 0) {
// 		close(sd);
// 		return -EIO;
// 	}

// 	memset((void *)&snl, 0, sizeof(struct sockaddr_nl));
// 	snl.nl_family = AF_NETLINK;
// 	snl.nl_pid = 0;

// 	if (connect(sd, (struct sockaddr *)&snl, sizeof(struct sockaddr_nl)) < 0) {
// 		close(sd);
// 		return -EIO;
// 	}

// 	return sd;
// }

// listenPacket creates a net.PacketConn which can be used to send and receive
// data at the device driver level.
func listenPacket(ifi *net.Interface, proto uint16) (*packetConn, error) {
	filename := "eth-packet-socket"
	// Open a packet socket using specified socket type. Do not specify
	// a protocol to avoid capturing packets which to not match cfg.Filter.
	// The later call to bind() will set up the correct protocol for us.
	sock, err := unix.Socket(unix.AF_NETLINK, unix.SOCK_RAW, syscall.NETLINK_ROUTE)
	if err != nil {
		return nil, err
	}

	if err := unix.SetNonblock(sock, true); err != nil {
		return nil, err
	}

	// When using Go 1.12+, the SetNonblock call we just did puts the file
	// descriptor into non-blocking mode. In that case, os.NewFile
	// registers the file descriptor with the runtime poller, which is then
	// used for all subsequent operations.
	//
	// See also: https://golang.org/pkg/os/#NewFile
	f := os.NewFile(uintptr(sock), filename)
	sc, err := f.SyscallConn()
	if err != nil {
		return nil, err
	}

	// Wrap raw socket in socket interface.
	pc, err := newPacketConn(ifi, &sysSocket{f: f, rc: sc}, htons(proto), nil)
	if err != nil {
		return nil, err
	}

	return pc, nil
}

// newPacketConn creates a net.PacketConn using the specified network
// interface, wrapped socket and big endian protocol number.
//
// It is the entry point for tests in this package.
func newPacketConn(ifi *net.Interface, s socket, pbe uint16, filter []bpf.RawInstruction) (*packetConn, error) {
	pc := &packetConn{
		ifi: ifi,
		s:   s,
		pbe: pbe,
	}

	// Bind the packet socket to the interface specified by ifi
	// packet(7):
	//   Only the sll_protocol and the sll_ifindex address fields are used for
	//   purposes of binding.
	// This overrides the protocol given to socket(AF_PACKET).
	// err := s.Bind(&unix.SockaddrLinklayer{
	// 	Protocol: pc.pbe,
	// 	Ifindex:  ifi.Index,
	// })
	// if err != nil {
	// 	return nil, err
	// }

	return pc, nil
}

// sysSocket is the default socket implementation.  It makes use of
// Linux-specific system calls to handle raw socket functionality.
type sysSocket struct {
	f  *os.File
	rc syscall.RawConn
}

func (s *sysSocket) SetDeadline(t time.Time) error {
	return s.f.SetDeadline(t)
}

func (s *sysSocket) SetReadDeadline(t time.Time) error {
	return s.f.SetReadDeadline(t)
}

func (s *sysSocket) SetWriteDeadline(t time.Time) error {
	return s.f.SetWriteDeadline(t)
}

func (s *sysSocket) Bind(sa unix.Sockaddr) error {
	var err error
	cerr := s.rc.Control(func(fd uintptr) {
		err = unix.Bind(int(fd), sa)
	})
	if err != nil {
		return err
	}
	return cerr
}

func (s *sysSocket) Close() error {
	return s.f.Close()
}

func (s *sysSocket) GetSockoptTpacketStats(level, name int) (*unix.TpacketStats, error) {
	var stats *unix.TpacketStats
	var err error
	cerr := s.rc.Control(func(fd uintptr) {
		s, errno := unix.GetsockoptTpacketStats(int(fd), level, name)
		stats = s
		if errno != nil {
			err = os.NewSyscallError("getsockopt", errno)
		}
	})
	if err != nil {
		return stats, err
	}
	return stats, cerr
}

func (s *sysSocket) Recvfrom(p []byte, flags int) (n int, addr unix.Sockaddr, err error) {
	cerr := s.rc.Read(func(fd uintptr) bool {
		n, addr, err = unix.Recvfrom(int(fd), p, flags)
		// When the socket is in non-blocking mode, we might see EAGAIN
		// and end up here. In that case, return false to let the
		// poller wait for readiness. See the source code for
		// internal/poll.FD.RawRead for more details.
		//
		// If the socket is in blocking mode, EAGAIN should never occur.
		return err != unix.EAGAIN
	})
	if err != nil {
		return n, addr, err
	}
	return n, addr, cerr
}

func (s *sysSocket) Sendto(p []byte, flags int, to unix.Sockaddr) error {
	var err error
	cerr := s.rc.Write(func(fd uintptr) bool {
		err = unix.Sendto(int(fd), p, flags, to)
		// See comment in Recvfrom.
		return err != unix.EAGAIN
	})
	if err != nil {
		return err
	}
	return cerr
}

func (s *sysSocket) SetSockoptSockFprog(level, name int, fprog *unix.SockFprog) error {
	var err error
	cerr := s.rc.Control(func(fd uintptr) {
		errno := unix.SetsockoptSockFprog(int(fd), level, name, fprog)
		if errno != nil {
			err = os.NewSyscallError("setsockopt", errno)
		}
	})
	if err != nil {
		return err
	}
	return cerr
}

func (s *sysSocket) SetSockoptPacketMreq(level, name int, mreq *unix.PacketMreq) error {
	var err error
	cerr := s.rc.Control(func(fd uintptr) {
		errno := unix.SetsockoptPacketMreq(int(fd), level, name, mreq)
		if errno != nil {
			err = os.NewSyscallError("setsockopt", errno)
		}
	})
	if err != nil {
		return err
	}
	return cerr
}
