// Copyright 2026 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     https://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package ldap

import (
	"encoding/asn1"
	"encoding/binary"
	"fmt"

	"github.com/mandiant/gopacket/pkg/kerberos"
	"github.com/mandiant/gopacket/pkg/third_party/gokrb5/crypto"
	"github.com/mandiant/gopacket/pkg/third_party/gokrb5/gssapi"
	"github.com/mandiant/gopacket/pkg/third_party/gokrb5/iana/keyusage"
	"github.com/mandiant/gopacket/pkg/third_party/gokrb5/messages"
	"github.com/mandiant/gopacket/pkg/third_party/gokrb5/types"
)

var oidKerberos = asn1.ObjectIdentifier{1, 2, 840, 113554, 1, 2, 2}

// KerberosGSSAPIClient implements go-ldap's GSSAPIClient interface.
type KerberosGSSAPIClient struct {
	krbClient  *kerberos.Client
	sessionKey types.EncryptionKey
}

// NewKerberosGSSAPIClient creates a GSSAPI client backed by the fork's
// proxy-aware Kerberos implementation.
func NewKerberosGSSAPIClient(krbClient *kerberos.Client) *KerberosGSSAPIClient {
	return &KerberosGSSAPIClient{krbClient: krbClient}
}

func (g *KerberosGSSAPIClient) InitSecContext(target string, token []byte) ([]byte, bool, error) {
	if token != nil {
		if len(token) > 0 {
			if err := g.acceptAPRep(token); err != nil {
				return nil, false, fmt.Errorf("accept Kerberos AP-REP: %w", err)
			}
		}
		return nil, false, nil
	}
	request, key, err := g.krbClient.GenerateSASLGSSAPReq(target)
	if err != nil {
		return nil, false, err
	}
	g.sessionKey = key
	wrapped, err := wrapGSSAPIToken(request)
	if err != nil {
		return nil, false, err
	}
	return wrapped, true, nil
}

func (g *KerberosGSSAPIClient) InitSecContextWithOptions(target string, token []byte, _ []int) ([]byte, bool, error) {
	return g.InitSecContext(target, token)
}

func (g *KerberosGSSAPIClient) NegotiateSaslAuth(token []byte, authzid string) ([]byte, error) {
	layers, err := g.securityLayers(token)
	if err != nil {
		return nil, err
	}
	response := make([]byte, 4+len(authzid))
	switch {
	case layers&0x01 != 0:
		response[0] = 0x01
	case layers&0x02 != 0:
		response[0] = 0x02
		response[2], response[3] = 0xff, 0xff
	case layers&0x04 != 0:
		response[0] = 0x04
		response[2], response[3] = 0xff, 0xff
	default:
		return nil, fmt.Errorf("LDAP server offered no supported GSSAPI security layer")
	}
	copy(response[4:], authzid)
	encType, err := crypto.GetEtype(g.sessionKey.KeyType)
	if err != nil {
		return nil, fmt.Errorf("select LDAP GSSAPI checksum: %w", err)
	}
	wrapped := &gssapi.WrapToken{
		Flags:     0x04,
		EC:        uint16(encType.GetHMACBitLength() / 8),
		SndSeqNum: 1,
		Payload:   response,
	}
	if err := wrapped.SetCheckSum(g.sessionKey, keyusage.GSSAPI_INITIATOR_SEAL); err != nil {
		return nil, fmt.Errorf("wrap LDAP GSSAPI response: %w", err)
	}
	encoded, err := wrapped.Marshal()
	if err != nil {
		return nil, fmt.Errorf("marshal LDAP GSSAPI response: %w", err)
	}
	return encoded, nil
}

func (g *KerberosGSSAPIClient) DeleteSecContext() error {
	g.sessionKey = types.EncryptionKey{}
	return nil
}

func (g *KerberosGSSAPIClient) securityLayers(token []byte) (byte, error) {
	wrapped, wrapErr := unmarshalAcceptorWrapToken(token)
	if wrapErr == nil {
		valid, verifyErr := wrapped.Verify(g.sessionKey, keyusage.GSSAPI_ACCEPTOR_SEAL)
		if verifyErr != nil {
			return 0, fmt.Errorf("verify LDAP GSSAPI wrap token: %w", verifyErr)
		}
		if !valid || len(wrapped.Payload) < 4 {
			return 0, fmt.Errorf("invalid LDAP GSSAPI wrap token")
		}
		return wrapped.Payload[0], nil
	}

	var mic gssapi.MICToken
	if err := mic.Unmarshal(token, true); err != nil {
		return 0, fmt.Errorf("decode LDAP GSSAPI security token: %w", err)
	}
	valid, err := mic.Verify(g.sessionKey, keyusage.GSSAPI_ACCEPTOR_SIGN)
	if err != nil {
		return 0, fmt.Errorf("verify LDAP GSSAPI MIC token: %w", err)
	}
	if !valid || len(mic.Payload) < 4 {
		return 0, fmt.Errorf("invalid LDAP GSSAPI MIC token")
	}
	return mic.Payload[0], nil
}

func unmarshalAcceptorWrapToken(token []byte) (*gssapi.WrapToken, error) {
	const headerLength = 16
	if len(token) < headerLength {
		return nil, fmt.Errorf("LDAP GSSAPI wrap token is shorter than its header")
	}
	if token[0] != 0x05 || token[1] != 0x04 {
		return nil, fmt.Errorf("unexpected LDAP GSSAPI wrap token ID")
	}
	flags := token[2]
	if flags&0x01 == 0 {
		return nil, fmt.Errorf("LDAP GSSAPI wrap token is not from the acceptor")
	}
	if flags&0x02 != 0 {
		return nil, fmt.Errorf("sealed LDAP GSSAPI negotiation token is unsupported")
	}
	if token[3] != gssapi.FillerByte {
		return nil, fmt.Errorf("invalid LDAP GSSAPI wrap token filler")
	}
	checksumLength := int(binary.BigEndian.Uint16(token[4:6]))
	body := token[headerLength:]
	if checksumLength > len(body) {
		return nil, fmt.Errorf("invalid LDAP GSSAPI wrap token checksum length")
	}
	rotation := int(binary.BigEndian.Uint16(token[6:8]))
	if len(body) > 0 {
		rotation %= len(body)
	}
	normalized := make([]byte, len(body))
	copy(normalized, body[rotation:])
	copy(normalized[len(body)-rotation:], body[:rotation])
	payloadLength := len(normalized) - checksumLength
	return &gssapi.WrapToken{
		Flags:     flags,
		EC:        uint16(checksumLength),
		RRC:       uint16(rotation),
		SndSeqNum: binary.BigEndian.Uint64(token[8:16]),
		Payload:   normalized[:payloadLength],
		CheckSum:  normalized[payloadLength:],
	}, nil
}

func (g *KerberosGSSAPIClient) acceptAPRep(token []byte) error {
	encoded, err := unwrapGSSAPIToken(token, 0x02, 0x00)
	if err != nil {
		return err
	}
	var reply messages.APRep
	if err := reply.Unmarshal(encoded); err != nil {
		return fmt.Errorf("decode AP-REP: %w", err)
	}
	plain, err := crypto.DecryptEncPart(reply.EncPart, g.sessionKey, uint32(keyusage.AP_REP_ENCPART))
	if err != nil {
		return fmt.Errorf("decrypt AP-REP: %w", err)
	}
	var part messages.EncAPRepPart
	if err := part.Unmarshal(plain); err != nil {
		return fmt.Errorf("decode AP-REP encrypted part: %w", err)
	}
	if len(part.Subkey.KeyValue) > 0 {
		g.sessionKey = part.Subkey
	}
	return nil
}

func unwrapGSSAPIToken(token []byte, firstID, secondID byte) ([]byte, error) {
	var outer asn1.RawValue
	rest, err := asn1.Unmarshal(token, &outer)
	if err != nil {
		return nil, fmt.Errorf("decode GSSAPI token: %w", err)
	}
	if len(rest) != 0 || outer.Class != asn1.ClassApplication || outer.Tag != 0 || !outer.IsCompound {
		return nil, fmt.Errorf("invalid GSSAPI application token")
	}
	var oid asn1.ObjectIdentifier
	payload, err := asn1.Unmarshal(outer.Bytes, &oid)
	if err != nil {
		return nil, fmt.Errorf("decode GSSAPI mechanism: %w", err)
	}
	if !oid.Equal(oidKerberos) {
		return nil, fmt.Errorf("unexpected GSSAPI mechanism %s", oid.String())
	}
	if len(payload) < 2 || payload[0] != firstID || payload[1] != secondID {
		return nil, fmt.Errorf("unexpected GSSAPI token ID")
	}
	return payload[2:], nil
}

func wrapGSSAPIToken(request []byte) ([]byte, error) {
	oid, err := asn1.Marshal(oidKerberos)
	if err != nil {
		return nil, err
	}
	inner := make([]byte, 0, len(oid)+2+len(request))
	inner = append(inner, oid...)
	inner = append(inner, 0x01, 0x00)
	inner = append(inner, request...)
	return wrapASN1Application(inner), nil
}

func wrapASN1Application(data []byte) []byte {
	length := len(data)
	switch {
	case length < 128:
		out := make([]byte, 2+length)
		out[0], out[1] = 0x60, byte(length)
		copy(out[2:], data)
		return out
	case length < 256:
		out := make([]byte, 3+length)
		out[0], out[1], out[2] = 0x60, 0x81, byte(length)
		copy(out[3:], data)
		return out
	default:
		out := make([]byte, 4+length)
		out[0], out[1], out[2], out[3] = 0x60, 0x82, byte(length>>8), byte(length)
		copy(out[4:], data)
		return out
	}
}
