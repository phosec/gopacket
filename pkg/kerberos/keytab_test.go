package kerberos

import (
	"bytes"
	"encoding/hex"
	"testing"

	"github.com/mandiant/gopacket/pkg/third_party/gokrb5/iana/etypeID"
	"github.com/mandiant/gopacket/pkg/third_party/gokrb5/iana/nametype"
	"github.com/mandiant/gopacket/pkg/third_party/gokrb5/types"
)

func TestBuildKeytabFromNTHashMatchesDirectoryKVNO(t *testing.T) {
	const hash = "94b83f71a963161dc0989118f7c3ab2e"
	kt, err := BuildKeytabFromNTHash("alice", "LAB.EXAMPLE.TEST", hash)
	if err != nil {
		t.Fatalf("BuildKeytabFromNTHash: %v", err)
	}

	key, kvno, err := kt.GetEncryptionKey(
		types.NewPrincipalName(nametype.KRB_NT_PRINCIPAL, "alice"),
		"LAB.EXAMPLE.TEST",
		42,
		etypeID.RC4_HMAC,
	)
	if err != nil {
		t.Fatalf("GetEncryptionKey with directory kvno: %v", err)
	}
	want, err := hex.DecodeString(hash)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(key.KeyValue, want) {
		t.Fatalf("key = %x, want %x", key.KeyValue, want)
	}
	if kvno != 0 {
		t.Fatalf("kvno = %d, want unversioned 0", kvno)
	}
}
