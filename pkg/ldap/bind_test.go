package ldap

import "testing"

func TestPasswordBindUsername(t *testing.T) {
	tests := map[string]struct {
		domain   string
		username string
		want     string
	}{
		"DNS domain uses UPN": {
			domain:   "LAB.EXAMPLE.TEST",
			username: "alice",
			want:     "alice@LAB.EXAMPLE.TEST",
		},
		"NetBIOS domain uses down-level name": {
			domain:   "LAB",
			username: "alice",
			want:     `LAB\alice`,
		},
		"empty domain keeps username": {
			username: "alice",
			want:     "alice",
		},
		"UPN stays qualified": {
			domain:   "LAB.EXAMPLE.TEST",
			username: "alice@alt.example",
			want:     "alice@alt.example",
		},
		"down-level ID stays qualified": {
			domain:   "LAB.EXAMPLE.TEST",
			username: `LAB\alice`,
			want:     `LAB\alice`,
		},
	}
	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			if got := passwordBindUsername(test.domain, test.username); got != test.want {
				t.Fatalf("passwordBindUsername(%q, %q)=%q, want %q", test.domain, test.username, got, test.want)
			}
		})
	}
}
