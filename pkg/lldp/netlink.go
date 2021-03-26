package lldp

import (
	"os"
	"syscall"

	"github.com/mdlayher/netlink"
	"golang.org/x/sys/unix"
)

type netlinkCon struct {
	socket int
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
func netlinkSocket(proto uint16) (*netlinkCon, error) {
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
	err = unix.Bind(sock, &unix.SockaddrNetlink{
		// Always used when binding netlink sockets.
		Family: unix.AF_NETLINK,
		// A bitmask of multicast groups to join on bind.
		// Typically set to zero.
		Groups: 0,
		// If you'd like, you can assign a PID for this socket
		// here, but in my experience, it's easier to leave
		// this set to zero and let netlink assign and manage
		// PIDs on its own.
		Pid: 0,
	})

	return &netlinkCon{socket: sock}, err
}

func (nl *netlinkCon) sendTo(b []byte) error {
	msg := messageBytes(b)
	msgBinary, err := msg.MarshalBinary()
	if err != nil {
		return err
	}
	err = unix.Sendto(nl.socket, msgBinary, 0, &unix.SockaddrNetlink{
		// Always used when sending on netlink sockets.
		Family: unix.AF_NETLINK,
	})
	return err
}

func messageBytes(b []byte) netlink.Message {
	msg := netlink.Message{
		Header: netlink.Header{
			// Length of header, plus payload.
			Length: 16 + uint32(len(b)),
			// Set to zero on requests.
			Type: 0,
			// Indicate that message is a request to the kernel.
			Flags: netlink.Request,
			// Sequence number selected at random.
			Sequence: 1,
			// PID set to process's ID.
			PID: uint32(os.Getpid()),
		},
		// An arbitrary byte payload. May be in a variety of formats.
		Data: b,
	}
	return msg
}
