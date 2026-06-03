package smb2

import (
	"os"

	. "github.com/mandiant/gopacket/pkg/third_party/smb2/internal/smb2"
)

// SecurityInformation selects the parts of a Windows security descriptor to
// query from an SMB object.
type SecurityInformation uint32

const (
	OwnerSecurityInformation SecurityInformation = 0x00000001
	GroupSecurityInformation SecurityInformation = 0x00000002
	DACLSecurityInformation  SecurityInformation = 0x00000004
	SACLSecurityInformation  SecurityInformation = 0x00000008
)

func newQuerySecurityInfoRequest(flags SecurityInformation, outputBufferLength uint32) *QueryInfoRequest {
	return &QueryInfoRequest{
		InfoType:              SMB2_0_INFO_SECURITY,
		FileInfoClass:         0,
		AdditionalInformation: uint32(flags),
		Flags:                 0,
		OutputBufferLength:    outputBufferLength,
	}
}

func querySecurityDesiredAccess(flags SecurityInformation) uint32 {
	access := uint32(READ_CONTROL)
	if flags&SACLSecurityInformation != 0 {
		access |= ACCESS_SYSTEM_SECURITY
	}
	return access
}

// QuerySecurityInfo returns a self-relative Windows security descriptor for f.
func (f *File) QuerySecurityInfo(flags SecurityInformation) ([]byte, error) {
	sd, err := f.querySecurityInfo(flags)
	if err != nil {
		return nil, &os.PathError{Op: "querySecurityInfo", Path: f.name, Err: err}
	}
	return sd, nil
}

func (f *File) querySecurityInfo(flags SecurityInformation) ([]byte, error) {
	req := newQuerySecurityInfoRequest(flags, uint32(f.maxTransactSize()))
	return f.queryInfo(req)
}

// QuerySecurityInfo opens name and returns its self-relative Windows security descriptor.
func (fs *Share) QuerySecurityInfo(name string, flags SecurityInformation) ([]byte, error) {
	name = normPath(name)

	if err := validatePath("querySecurityInfo", name, false); err != nil {
		return nil, err
	}

	create := &CreateRequest{
		SecurityFlags:        0,
		RequestedOplockLevel: SMB2_OPLOCK_LEVEL_NONE,
		ImpersonationLevel:   Impersonation,
		SmbCreateFlags:       0,
		DesiredAccess:        querySecurityDesiredAccess(flags),
		FileAttributes:       FILE_ATTRIBUTE_NORMAL,
		ShareAccess:          FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
		CreateDisposition:    FILE_OPEN,
		CreateOptions:        0,
	}

	f, err := fs.createFile(name, create, true)
	if err != nil {
		return nil, &os.PathError{Op: "querySecurityInfo", Path: name, Err: err}
	}

	sd, err := f.querySecurityInfo(flags)
	if e := f.close(); err == nil {
		err = e
	}
	if err != nil {
		return nil, &os.PathError{Op: "querySecurityInfo", Path: name, Err: err}
	}
	return sd, nil
}
