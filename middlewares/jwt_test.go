package middlewares

import "testing"

func TestExtractToken(t *testing.T) {
	cases := []struct {
		name   string
		header string
		want   string
	}{
		{name: "plain token", header: "abc.def.ghi", want: "abc.def.ghi"},
		{name: "bearer token", header: "Bearer abc.def.ghi", want: "abc.def.ghi"},
		{name: "bearer token lowercase", header: "bearer abc.def.ghi", want: "abc.def.ghi"},
		{name: "token with spaces", header: "  Bearer   abc.def.ghi   ", want: "abc.def.ghi"},
		{name: "empty", header: "   ", want: ""},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := extractToken(tc.header)
			if got != tc.want {
				t.Fatalf("extractToken(%q) = %q, want %q", tc.header, got, tc.want)
			}
		})
	}
}
