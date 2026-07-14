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
	"fmt"
	"strings"

	"github.com/mandiant/gopacket/pkg/kerberos"
)

// Login attempts to bind to the LDAP server using the session credentials.
// Supports password, NTLM hash, and Kerberos authentication.
func (c *Client) Login() error {
	if c.Conn == nil {
		return fmt.Errorf("connection not established")
	}

	// Check authentication method in priority order
	if c.Session.UseKerberos {
		return c.LoginWithKerberos()
	}

	if c.Session.Hash != "" {
		return c.LoginWithHash()
	}

	// Use password auth
	bindUser := c.Session.Username
	if c.Session.Domain != "" {
		bindUser = fmt.Sprintf("%s\\%s", c.Session.Domain, c.Session.Username)
	}
	return c.LoginWithUser(bindUser)
}

// LoginWithKerberos performs Kerberos GSSAPI SASL bind.
func (c *Client) LoginWithKerberos() error {
	if c.Conn == nil {
		return fmt.Errorf("connection not established")
	}

	krbClient, err := kerberos.NewClientFromSession(c.Session, c.Target, c.Session.DCIP)
	if err != nil {
		return fmt.Errorf("failed to create kerberos client: %v", err)
	}
	return c.loginWithKerberosClient(krbClient)
}

func (c *Client) loginWithKerberosClient(krbClient *kerberos.Client) error {
	gssClient := NewKerberosGSSAPIClient(krbClient)
	spn := fmt.Sprintf("ldap/%s", c.Target.Host)
	if err := c.Conn.GSSAPIBind(gssClient, spn, ""); err != nil {
		return fmt.Errorf("GSSAPI bind failed: %v", err)
	}
	return nil
}

// LoginWithHash first uses the NT hash as a Kerberos RC4-HMAC key for a
// standards-based GSSAPI SASL bind. This works with Samba AD, which advertises
// SASL NTLM but does not implement Microsoft's LDAP Sicily bind exchange.
// Microsoft AD can still use the existing Sicily path when Kerberos is
// unavailable.
func (c *Client) LoginWithHash() error {
	if c.Conn == nil {
		return fmt.Errorf("connection not established")
	}

	var kerberosErr error
	if c.Session.Domain != "" {
		krbClient, err := kerberos.NewClientWithNTHash(c.Session, c.Target, c.Session.DCIP)
		if err == nil {
			if err = c.loginWithKerberosClient(krbClient); err == nil {
				return nil
			}
		}
		kerberosErr = err
	}

	hash := c.Session.Hash
	if parts := strings.SplitN(hash, ":", 2); len(parts) == 2 {
		hash = parts[1]
	}
	domain := c.Session.Domain
	if domain == "" {
		domain = "WORKGROUP"
	}
	if err := c.Conn.NTLMBindWithHash(domain, c.Session.Username, hash); err != nil {
		if kerberosErr != nil {
			return fmt.Errorf("Kerberos hash bind failed: %v; NTLM bind failed: %v", kerberosErr, err)
		}
		return fmt.Errorf("NTLM bind failed: %v", err)
	}
	return nil
}

// LoginWithUser attempts to bind using a specific username and the session password.
func (c *Client) LoginWithUser(username string) error {
	if c.Conn == nil {
		return fmt.Errorf("connection not established")
	}

	// Check if we have an NTLM hash - if so, use NTLM bind
	if c.Session.Hash != "" {
		return c.LoginWithHash()
	}

	err := c.Conn.Bind(username, c.Session.Password)
	if err != nil {
		return fmt.Errorf("bind failed: %v", err)
	}

	return nil
}
