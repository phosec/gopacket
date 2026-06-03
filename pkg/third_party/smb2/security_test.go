package smb2

import (
	"testing"

	. "github.com/mandiant/gopacket/pkg/third_party/smb2/internal/smb2"
)

func TestSecurityInformationConstants(t *testing.T) {
	tests := []struct {
		name string
		got  SecurityInformation
		want uint32
	}{
		{name: "owner", got: OwnerSecurityInformation, want: 0x00000001},
		{name: "group", got: GroupSecurityInformation, want: 0x00000002},
		{name: "dacl", got: DACLSecurityInformation, want: 0x00000004},
		{name: "sacl", got: SACLSecurityInformation, want: 0x00000008},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if uint32(tc.got) != tc.want {
				t.Fatalf("got 0x%08x, want 0x%08x", uint32(tc.got), tc.want)
			}
		})
	}
}

func TestQuerySecurityDesiredAccess(t *testing.T) {
	if got := querySecurityDesiredAccess(OwnerSecurityInformation | GroupSecurityInformation | DACLSecurityInformation); got != READ_CONTROL {
		t.Fatalf("DACL query desired access got 0x%08x, want READ_CONTROL 0x%08x", got, uint32(READ_CONTROL))
	}

	want := uint32(READ_CONTROL | ACCESS_SYSTEM_SECURITY)
	if got := querySecurityDesiredAccess(SACLSecurityInformation); got != want {
		t.Fatalf("SACL query desired access got 0x%08x, want 0x%08x", got, want)
	}
}

func TestNewQuerySecurityInfoRequest(t *testing.T) {
	flags := OwnerSecurityInformation | GroupSecurityInformation | DACLSecurityInformation
	req := newQuerySecurityInfoRequest(flags, 4096)

	if req.InfoType != SMB2_0_INFO_SECURITY {
		t.Fatalf("InfoType got %d, want SMB2_0_INFO_SECURITY %d", req.InfoType, SMB2_0_INFO_SECURITY)
	}
	if req.FileInfoClass != 0 {
		t.Fatalf("FileInfoClass got %d, want 0", req.FileInfoClass)
	}
	if req.AdditionalInformation != uint32(flags) {
		t.Fatalf("AdditionalInformation got 0x%08x, want 0x%08x", req.AdditionalInformation, uint32(flags))
	}
	if req.Flags != 0 {
		t.Fatalf("Flags got 0x%08x, want 0", req.Flags)
	}
	if req.OutputBufferLength != 4096 {
		t.Fatalf("OutputBufferLength got %d, want 4096", req.OutputBufferLength)
	}
}
