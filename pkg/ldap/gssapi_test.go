package ldap

import (
	"bytes"
	stdasn1 "encoding/asn1"
	"encoding/binary"
	"testing"
	"time"

	forkasn1 "github.com/jcmturner/gofork/encoding/asn1"
	"github.com/mandiant/gopacket/pkg/third_party/gokrb5/asn1tools"
	"github.com/mandiant/gopacket/pkg/third_party/gokrb5/crypto"
	"github.com/mandiant/gopacket/pkg/third_party/gokrb5/gssapi"
	"github.com/mandiant/gopacket/pkg/third_party/gokrb5/iana"
	"github.com/mandiant/gopacket/pkg/third_party/gokrb5/iana/asnAppTag"
	"github.com/mandiant/gopacket/pkg/third_party/gokrb5/iana/keyusage"
	"github.com/mandiant/gopacket/pkg/third_party/gokrb5/iana/msgtype"
	"github.com/mandiant/gopacket/pkg/third_party/gokrb5/messages"
	"github.com/mandiant/gopacket/pkg/third_party/gokrb5/types"
)

func TestKerberosGSSAPIClientAcceptAPRepUsesAcceptorSubkey(t *testing.T) {
	sessionKey := types.EncryptionKey{KeyType: 18, KeyValue: bytes.Repeat([]byte{0x11}, 32)}
	acceptorSubkey := types.EncryptionKey{KeyType: 18, KeyValue: bytes.Repeat([]byte{0x22}, 32)}
	part := messages.EncAPRepPart{
		CTime:  time.Now().UTC().Truncate(time.Second),
		Cusec:  1,
		Subkey: acceptorSubkey,
	}
	plain, err := forkasn1.Marshal(part)
	if err != nil {
		t.Fatalf("marshal AP-REP part: %v", err)
	}
	plain = asn1tools.AddASNAppTag(plain, asnAppTag.EncAPRepPart)
	encrypted, err := crypto.GetEncryptedData(plain, sessionKey, uint32(keyusage.AP_REP_ENCPART), 0)
	if err != nil {
		t.Fatalf("encrypt AP-REP part: %v", err)
	}
	reply := messages.APRep{PVNO: iana.PVNO, MsgType: msgtype.KRB_AP_REP, EncPart: encrypted}
	encoded, err := forkasn1.Marshal(reply)
	if err != nil {
		t.Fatalf("marshal AP-REP: %v", err)
	}
	encoded = asn1tools.AddASNAppTag(encoded, asnAppTag.APREP)
	oid, err := stdasn1.Marshal(oidKerberos)
	if err != nil {
		t.Fatalf("marshal Kerberos OID: %v", err)
	}
	inner := append(append(oid, 0x02, 0x00), encoded...)

	client := &KerberosGSSAPIClient{sessionKey: sessionKey}
	if err := client.acceptAPRep(wrapASN1Application(inner)); err != nil {
		t.Fatalf("acceptAPRep: %v", err)
	}
	if client.sessionKey.KeyType != acceptorSubkey.KeyType || !bytes.Equal(client.sessionKey.KeyValue, acceptorSubkey.KeyValue) {
		t.Fatalf("session key = %#v, want acceptor subkey", client.sessionKey)
	}
}

func TestKerberosGSSAPIClientAcceptsRotatedSambaSecurityLayerToken(t *testing.T) {
	sessionKey := types.EncryptionKey{KeyType: 18, KeyValue: bytes.Repeat([]byte{0x33}, 32)}
	wrapped := &gssapi.WrapToken{
		Flags:     0x01,
		EC:        12,
		SndSeqNum: 0,
		Payload:   []byte{0x01, 0x00, 0x00, 0x00},
	}
	if err := wrapped.SetCheckSum(sessionKey, keyusage.GSSAPI_ACCEPTOR_SEAL); err != nil {
		t.Fatalf("set checksum: %v", err)
	}
	encoded, err := wrapped.Marshal()
	if err != nil {
		t.Fatalf("marshal wrap token: %v", err)
	}
	body := append([]byte(nil), encoded[16:]...)
	rotation := len(wrapped.CheckSum)
	copy(encoded[16:], append(body[len(body)-rotation:], body[:len(body)-rotation]...))
	binary.BigEndian.PutUint16(encoded[6:8], uint16(rotation))

	client := &KerberosGSSAPIClient{sessionKey: sessionKey}
	layer, err := client.securityLayers(encoded)
	if err != nil {
		t.Fatalf("securityLayers: %v", err)
	}
	if layer != 0x01 {
		t.Fatalf("security layer = %#x, want no-layer capability", layer)
	}
}
