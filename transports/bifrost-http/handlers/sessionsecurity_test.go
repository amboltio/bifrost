package handlers

import (
	"testing"

	"github.com/valyala/fasthttp"
)

func TestAllowSessionStateChangeRejectsCrossSiteOrigins(t *testing.T) {
	for _, test := range []struct {
		name   string
		origin string
		fetch  string
		want   bool
	}{
		{name: "same origin", origin: "https://gateway.example.test", want: true},
		{name: "different origin", origin: "https://attacker.example.test", want: false},
		{name: "malformed origin", origin: "not a URL", want: false},
		{name: "cross-site fetch without origin", fetch: "cross-site", want: false},
		{name: "non-browser request", want: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			ctx := &fasthttp.RequestCtx{}
			ctx.Request.SetHost("gateway.example.test")
			if test.origin != "" {
				ctx.Request.Header.Set("Origin", test.origin)
			}
			if test.fetch != "" {
				ctx.Request.Header.Set("Sec-Fetch-Site", test.fetch)
			}
			if got := allowSessionStateChange(ctx); got != test.want {
				t.Fatalf("allowSessionStateChange() = %v, want %v", got, test.want)
			}
		})
	}
}
