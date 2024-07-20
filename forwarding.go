package nebula

import (
	"context"
	"fmt"
	"io"
	"net"
	"strconv"
	"strings"
	"sync"

	"github.com/sirupsen/logrus"
	"github.com/slackhq/nebula/config"
	"github.com/slackhq/nebula/overlay"
	"gvisor.dev/gvisor/pkg/buffer"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/adapters/gonet"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/link/channel"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv4"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv6"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
	"gvisor.dev/gvisor/pkg/tcpip/transport/icmp"
	"gvisor.dev/gvisor/pkg/tcpip/transport/tcp"
	"gvisor.dev/gvisor/pkg/tcpip/transport/udp"
	"gvisor.dev/gvisor/pkg/waiter"
)

const nicID = 1

type Session struct {
	ctx    context.Context
	cancel context.CancelFunc
	dial   string
	s      *stack.Stack
}

type Forwarder struct {
	ctx context.Context
	l   *logrus.Logger
	c   *config.C
	s   *stack.Stack
	mu  struct {
		sync.Mutex

		incomingTcp map[uint16]*Session
		outgoingTcp map[string]*Session
	}
}

func setupForwarding(l *logrus.Logger, c *config.C, dev *overlay.UserDevice) error {
	ctx := context.Background()

	s := stack.New(stack.Options{
		NetworkProtocols:   []stack.NetworkProtocolFactory{ipv4.NewProtocol, ipv6.NewProtocol},
		TransportProtocols: []stack.TransportProtocolFactory{tcp.NewProtocol, udp.NewProtocol, icmp.NewProtocol4, icmp.NewProtocol6},
	})

	linkEP := channel.New( /*size*/ 512 /*mtu*/, 1280, "")
	if tcpipProblem := s.CreateNIC(nicID, linkEP); tcpipProblem != nil {
		return fmt.Errorf("failed to create NIC")
	}

	ipv4Subnet, _ := tcpip.NewSubnet(tcpip.AddrFrom4([4]byte{0x00, 0x00, 0x00, 0x00}), tcpip.MaskFrom(strings.Repeat("\x00", 4)))
	s.SetRouteTable([]tcpip.Route{
		{
			Destination: ipv4Subnet,
			NIC:         nicID,
		},
	})
	s.SetPromiscuousMode(nicID, true)

	ipNet := dev.Cidr()
	pa := tcpip.ProtocolAddress{
		AddressWithPrefix: tcpip.AddrFromSlice(ipNet.IP).WithPrefix(),
		Protocol:          ipv4.ProtocolNumber,
	}
	if err := s.AddProtocolAddress(nicID, pa, stack.AddressProperties{
		PEB:        stack.CanBePrimaryEndpoint, // zero value default
		ConfigType: stack.AddressConfigStatic,  // zero value default
	}); err != nil {
		return fmt.Errorf("failed to set protocol address")
	}

	f := NewForwarder(ctx, l, c, s)

	const tcpReceiveBufferSize = 0
	const maxInFlightConnectionAttempts = 1024
	tcpFwd := tcp.NewForwarder(s, tcpReceiveBufferSize, maxInFlightConnectionAttempts, f.tcpHandler)
	s.SetTransportProtocolHandler(tcp.ProtocolNumber, tcpFwd.HandlePacket)

	reader, writer := dev.Pipe()

	go func() error {
		buf := make([]byte, mtu)
		for {
			n, err := reader.Read(buf)
			if err != nil {
				return err
			}
			packetBuf := stack.NewPacketBuffer(stack.PacketBufferOptions{
				Payload: buffer.MakeWithData(buf[:n]),
			})
			linkEP.InjectInbound(header.IPv4ProtocolNumber, packetBuf)

			if err := ctx.Err(); err != nil {
				return err
			}
		}
	}()
	go func() error {
		for {
			packet := linkEP.ReadContext(ctx)
			if packet == nil {
				if err := ctx.Err(); err != nil {
					return err
				}
				continue
			}
			bufView := packet.ToView()
			if _, err := bufView.WriteTo(writer); err != nil {
				return err
			}
			bufView.Release()
		}
	}()

	f.addInbound()
	f.addOutbound()

	return nil
}

func (f *Forwarder) addInbound() {
	r := f.c.Get("forwarding.inbound")
	if r == nil {
		return
	}

	rs, ok := r.([]interface{})
	if !ok {
		return
	}

	for _, rule := range rs {
		rule, ok := rule.(map[interface{}]interface{})
		if !ok {
			f.l.Warn("Failed to get inbound")
			continue
		}
		dial, ok := rule["dial"].(string)
		if !ok {
			f.l.Warn("Failed to get dial")
			continue
		}
		listen, ok := rule["listen"].(string)
		if !ok {
			f.l.Warn("Failed to get listen")
			continue
		}
		listenPortStr := strings.Split(listen, ":")[1]
		listenPort, err := strconv.Atoi(listenPortStr)
		if err != nil {
			f.l.Warn("Failed to parse int")
			continue
		}

		ctx, cancel := context.WithCancel(f.ctx)
		f.mu.incomingTcp[uint16(listenPort)] = &Session{ctx: ctx, cancel: cancel, dial: dial}
		f.l.Infof("Forwarding incoming %d", listenPort)
	}
}

func (f *Forwarder) addOutbound() {
	r := f.c.Get("forwarding.outbound")
	if r == nil {
		return
	}

	rs, ok := r.([]interface{})
	if !ok {
		return
	}

	for _, rule := range rs {
		rule, ok := rule.(map[interface{}]interface{})
		if !ok {
			f.l.Warn("Failed to get inbound")
			continue
		}
		dial, ok := rule["dial"].(string)
		if !ok {
			f.l.Warn("Failed to get dial")
			continue
		}
		listen, ok := rule["listen"].(string)
		if !ok {
			f.l.Warn("Failed to get listen")
			continue
		}

		ctx, cancel := context.WithCancel(f.ctx)
		s := &Session{ctx: ctx, cancel: cancel, dial: dial, s: f.s}
		f.mu.outgoingTcp[listen] = s
		go f.listenLocal(s, listen)
	}
}

func NewForwarder(ctx context.Context, l *logrus.Logger, c *config.C, s *stack.Stack) *Forwarder {
	return &Forwarder{
		ctx: ctx,
		l:   l,
		c:   c,
		s:   s,
		mu: struct {
			sync.Mutex
			incomingTcp map[uint16]*Session
			outgoingTcp map[string]*Session
		}{
			incomingTcp: make(map[uint16]*Session),
			outgoingTcp: make(map[string]*Session),
		},
	}
}

func (f *Forwarder) tcpHandler(req *tcp.ForwarderRequest) {
	endpointID := req.ID()
	f.mu.Lock()
	defer f.mu.Unlock()

	l, ok := f.mu.incomingTcp[endpointID.LocalPort]
	if !ok {
		req.Complete(true)
		return
	}

	var wq waiter.Queue
	ep, err := req.CreateEndpoint(&wq)
	if err != nil {
		req.Complete(true)
		return
	}
	req.Complete(false)
	ep.SocketOptions().SetKeepAlive(true)

	conn := gonet.NewTCPConn(&wq, ep)

	ctx, cancelFn := context.WithCancel(l.ctx)
	go func() {
		defer conn.Close()

		var d net.Dialer
		forwardConn, err := d.DialContext(ctx, "tcp", l.dial)
		if err != nil {
			f.l.Warnf("Failed to dial to local server %s", l.dial)
			// Do nothing.
			return
		}

		go func() {
			io.Copy(conn, forwardConn)
			cancelFn()
		}()
		go func() {
			io.Copy(forwardConn, conn)
			cancelFn()
		}()
		<-ctx.Done()
		f.l.Info("Closing tcp forwarding session")
	}()
}

func (f *Forwarder) listenLocal(s *Session, bind string) {
	var lc net.ListenConfig
	listener, err := lc.Listen(s.ctx, "tcp", bind)
	if err != nil {
		return
	}
	defer listener.Close()

	for {
		conn, err := listener.Accept()
		if err != nil {
			return
		}
		go f.forwardOutboundTcp(s, conn)
	}
}

func (f *Forwarder) forwardOutboundTcp(s *Session, c net.Conn) {
	defer c.Close()
	ctx, cancelFn := context.WithCancel(s.ctx)
	addr, err := net.ResolveTCPAddr("tcp", s.dial)
	if err != nil {
		cancelFn()
		return
	}

	fullAddr := tcpip.FullAddress{
		NIC:  nicID,
		Addr: tcpip.AddrFromSlice(addr.IP),
		Port: uint16(addr.Port),
	}

	forwardConn, err := gonet.DialContextTCP(ctx, f.s, fullAddr, ipv4.ProtocolNumber)
	if err != nil {
		f.l.Errorf("Failed to establish nebula connection with %s", s.dial)
	}
	defer forwardConn.Close()

	go func() {
		io.Copy(forwardConn, c)
		cancelFn()
	}()
	go func() {
		io.Copy(c, forwardConn)
		cancelFn()
	}()

	<-ctx.Done()
}
