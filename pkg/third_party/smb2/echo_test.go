package smb2

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"

	. "github.com/mandiant/gopacket/pkg/third_party/smb2/internal/smb2"
)

func TestEchoRequestEncode(t *testing.T) {
	req := new(EchoRequest)
	req.CreditCharge = 1

	if got, want := req.Size(), 64+4; got != want {
		t.Fatalf("Size got %d, want %d", got, want)
	}

	pkt := make([]byte, req.Size())
	req.Encode(pkt)

	p := PacketCodec(pkt)
	if p.IsInvalid() {
		t.Fatal("encoded echo request has invalid SMB2 header")
	}
	if got := p.Command(); got != SMB2_ECHO {
		t.Fatalf("Command got %d, want SMB2_ECHO %d", got, SMB2_ECHO)
	}
	if got, want := len(pkt), 68; got != want {
		t.Fatalf("encoded packet length got %d, want %d", got, want)
	}

	body := p.Data()
	if got, want := len(body), 4; got != want {
		t.Fatalf("body length got %d, want %d", got, want)
	}
	r := EchoRequestDecoder(body)
	if r.IsInvalid() {
		t.Fatal("encoded echo request body is invalid")
	}
	if got, want := r.StructureSize(), uint16(4); got != want {
		t.Fatalf("StructureSize got %d, want %d", got, want)
	}
	if body[2] != 0 || body[3] != 0 {
		t.Fatalf("reserved bytes got %#v, want zeros", body[2:4])
	}
}

func TestEchoResponseDecoder(t *testing.T) {
	res := new(EchoResponse)

	if got, want := res.Size(), 64+4; got != want {
		t.Fatalf("Size got %d, want %d", got, want)
	}

	pkt := make([]byte, res.Size())
	res.Encode(pkt)

	p := PacketCodec(pkt)
	if p.IsInvalid() {
		t.Fatal("encoded echo response has invalid SMB2 header")
	}
	if got := p.Command(); got != SMB2_ECHO {
		t.Fatalf("Command got %d, want SMB2_ECHO %d", got, SMB2_ECHO)
	}

	r := EchoResponseDecoder(p.Data())
	if r.IsInvalid() {
		t.Fatal("encoded echo response body is invalid")
	}
	if got, want := r.StructureSize(), uint16(4); got != want {
		t.Fatalf("StructureSize got %d, want %d", got, want)
	}

	if !EchoResponseDecoder([]byte{4, 0, 0}).IsInvalid() {
		t.Fatal("short echo response body should be invalid")
	}
	if !EchoResponseDecoder([]byte{5, 0, 0, 0}).IsInvalid() {
		t.Fatal("wrong echo response structure size should be invalid")
	}
}

func TestSessionEchoUsesSessionSendRecv(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()

	conn := &conn{
		outstandingRequests: newOutstandingRequests(),
		sequenceWindow:      42,
		account:             openAccount(1),
		write:               make(chan []byte, 1),
		werr:                make(chan error, 1),
	}
	sess := &session{
		conn:         conn,
		sessionFlags: SMB2_SESSION_FLAG_IS_GUEST,
		sessionId:    0x0102030405060708,
	}
	conn.session = sess

	errCh := make(chan error, 1)
	go func() {
		pkt := <-conn.write
		p := PacketCodec(pkt)

		if err := validateEchoRequestPacket(p, sess.sessionId); err != nil {
			conn.werr <- err
			errCh <- err
			return
		}

		rr, ok := conn.outstandingRequests.pop(p.MessageId())
		if !ok {
			err := errors.New("echo request was not registered as outstanding")
			conn.werr <- err
			errCh <- err
			return
		}

		res := &EchoResponse{
			PacketHeader: PacketHeader{
				CreditRequestResponse: 1,
				Flags:                 SMB2_FLAGS_SERVER_TO_REDIR,
				MessageId:             p.MessageId(),
				SessionId:             p.SessionId(),
			},
		}
		resPkt := make([]byte, res.Size())
		res.Encode(resPkt)

		conn.werr <- nil
		rr.recv <- resPkt
		errCh <- nil
	}()

	client := (&Session{s: sess, ctx: context.Background()}).WithContext(ctx)
	if err := client.Echo(); err != nil {
		t.Fatalf("Echo returned error: %v", err)
	}
	if err := <-errCh; err != nil {
		t.Fatal(err)
	}
}

func validateEchoRequestPacket(p PacketCodec, sessionId uint64) error {
	if p.IsInvalid() {
		return errors.New("echo request has invalid SMB2 header")
	}
	if got := p.Command(); got != SMB2_ECHO {
		return fmt.Errorf("command got %d, want SMB2_ECHO %d", got, SMB2_ECHO)
	}
	if got := p.SessionId(); got != sessionId {
		return fmt.Errorf("session id got 0x%016x, want 0x%016x", got, sessionId)
	}
	if got := p.TreeId(); got != 0 {
		return fmt.Errorf("tree id got %d, want 0", got)
	}
	if r := EchoRequestDecoder(p.Data()); r.IsInvalid() {
		return errors.New("echo request body is invalid")
	}
	return nil
}
