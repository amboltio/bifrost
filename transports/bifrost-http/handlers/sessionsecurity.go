package handlers

import (
	"net/url"
	"strings"
	"time"

	"github.com/valyala/fasthttp"
)

// allowSessionStateChange rejects browser cross-site requests before a cookie
// can mutate an authenticated session. Non-browser callers may omit Origin;
// an explicit cross-site Fetch Metadata signal is still refused in that case.
func allowSessionStateChange(ctx *fasthttp.RequestCtx) bool {
	origin := strings.TrimSpace(string(ctx.Request.Header.Peek("Origin")))
	if origin == "" {
		return strings.ToLower(strings.TrimSpace(string(ctx.Request.Header.Peek("Sec-Fetch-Site")))) != "cross-site"
	}
	parsed, err := url.Parse(origin)
	if err != nil || (parsed.Scheme != "http" && parsed.Scheme != "https") || parsed.Host == "" || parsed.User != nil {
		return false
	}
	return strings.EqualFold(parsed.Host, string(ctx.Host()))
}

// setSessionCookie is the single session-cookie writer. Secure is based only
// on the TLS connection visible to this process: a user-supplied forwarded
// header must never change an authentication cookie's security attributes.
// Deployments that terminate TLS upstream must preserve a trusted TLS hop to
// Bifrost before relying on Secure cookies.
func setSessionCookie(ctx *fasthttp.RequestCtx, token string, expiresAt time.Time) {
	cookie := fasthttp.AcquireCookie()
	defer fasthttp.ReleaseCookie(cookie)
	cookie.SetKey("token")
	cookie.SetValue(token)
	cookie.SetExpire(expiresAt)
	cookie.SetPath("/")
	cookie.SetHTTPOnly(true)
	cookie.SetSameSite(fasthttp.CookieSameSiteLaxMode)
	cookie.SetSecure(ctx.IsTLS())
	ctx.Response.Header.SetCookie(cookie)
}

func clearSessionCookie(ctx *fasthttp.RequestCtx) {
	setSessionCookie(ctx, "", time.Now().Add(-24*time.Hour))
}
