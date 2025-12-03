package main

import (
    "crypto/hmac"
    "crypto/sha256"
    "crypto/tls"
    "encoding/base64"
    "encoding/json"
    "errors"
    "net/http"
    "os"
    "strings"
    "sync"
    "time"

    "github.com/kiwiirc/webircgateway/pkg/webircgateway"
)

// Configurable via env on the gateway process
var (
    authMeURL     = getenv("WEBIRC_AUTHBEARER_ME_URL", "https://bb.chat/oauth/me")
    sharedSecret  = getenv("WEBIRC_AUTHBEARER_SHARED_SECRET", "") // optional: if set, accept HS256 id_tokens with this secret
    allowInsecure = getenv("WEBIRC_AUTHBEARER_INSECURE", "false") == "true"
)

// Simple cache to avoid hammering the auth endpoint on reconnects
var tokenCache = NewLRUCache(128, 30*time.Second)

func Start(gateway *webircgateway.Gateway, pluginsQuit *sync.WaitGroup) {
    gateway.Log(1, "authbearer plugin loading")

    webircgateway.HookRegister("irc.connection.pre", func(h *webircgateway.HookIrcConnectionPre) {
        client := h.Client

        client.Log(1, "authbearer: tags=%v", client.Tags)
        token := extractToken(client)
        if token == "" {
            client.Log(2, "authbearer: no token found; skipping")
            return
        }

        claims, err := validateToken(token)
        if err != nil {
            client.Log(3, "authbearer: token invalid: %s", err.Error())
            return
        }

        // username precedence: preferred_username, username, user_login, email prefix
        username := pickUsername(claims)
        if username == "" {
            client.Log(3, "authbearer: no username claim")
            return
        }

        // Set IRC state / upstream credentials
        client.IrcState.Username = username
        client.IrcState.Nick = username
        client.IrcState.RealName = username

        // Send the raw access token as the SASL password; Anope validates it via OAuth.
        tok := strings.TrimLeft(token, ":")
        saslPass := tok
        client.IrcState.Password = saslPass

        // Ask the gateway to perform SASL PLAIN upstream
        client.UpstreamConfig.Sasl = &webircgateway.ConfigSasl{
            Enabled:  true,
            Mechanism: "PLAIN",
            Account:  username,
            Password: saslPass,
        }

        client.Log(2, "authbearer: using SASL for %s", username)
    })

    pluginsQuit.Done()
}

// Extract token from common locations
func extractToken(c *webircgateway.Client) string {
    // Prefer explicit token tag set by transport
    if tok, ok := c.Tags["jwt"]; ok && tok != "" {
        return tok
    }
    return ""
}

func validateToken(token string) (map[string]interface{}, error) {
    if cached, ok := tokenCache.Get(token); ok {
        return cached, nil
    }

    claims := make(map[string]interface{})

    // Hit /me with bearer token (strip any leading colon that may appear in SASL payload)
    req, _ := http.NewRequest("GET", authMeURL, nil)
    tok := strings.TrimLeft(token, ":")
    req.Header.Set("Authorization", "Bearer "+tok)

    client := &http.Client{Timeout: 5 * time.Second}
    if allowInsecure {
        client.Transport = insecureTransport()
    }

    resp, err := client.Do(req)
    if err == nil && resp.StatusCode >= 200 && resp.StatusCode < 300 {
        defer resp.Body.Close()
        dec := json.NewDecoder(resp.Body)
        dec.UseNumber()
        if err := dec.Decode(&claims); err == nil {
            tokenCache.Set(token, claims)
            return claims, nil
        }
    }

    // Fallback: attempt to decode id_token locally if HS256 and secret provided
    if sharedSecret != "" {
        if parsed, err := parseHS256IDToken(token, sharedSecret); err == nil {
            tokenCache.Set(token, parsed)
            return parsed, nil
        }
    }

    return nil, errors.New("auth failed")
}

func pickUsername(claims map[string]interface{}) string {
    keys := []string{"preferred_username", "username", "user_login", "user_nicename"}
    for _, k := range keys {
        if v, ok := claims[k]; ok {
            if s, ok := v.(string); ok && s != "" {
                return sanitize(s)
            }
        }
    }
    // email prefix fallback
    if v, ok := claims["email"]; ok {
        if s, ok := v.(string); ok && s != "" {
            if i := strings.IndexByte(s, '@'); i > 0 {
                return sanitize(s[:i])
            }
        }
    }
    return ""
}

func sanitize(in string) string {
    in = strings.TrimSpace(in)
    out := make([]rune, 0, len(in))
    for _, r := range in {
        if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') || r == '_' || r == '-' {
            out = append(out, r)
        }
    }
    if len(out) == 0 {
        return ""
    }
    if out[0] >= '0' && out[0] <= '9' {
        out = append([]rune{'u', '_'}, out...)
    }
    return string(out)
}

func derivePassword(username, token string) string {
    // Deprecated: no longer used; kept for compatibility.
    h := hmac.New(sha256.New, []byte(username))
    h.Write([]byte(token))
    return base64.StdEncoding.EncodeToString(h.Sum(nil))
}

// Minimal HS256 parser for id_token fallback
func parseHS256IDToken(tok, secret string) (map[string]interface{}, error) {
    parts := strings.Split(tok, ".")
    if len(parts) != 3 {
        return nil, errors.New("bad jwt")
    }
    sigInput := strings.Join(parts[0:2], ".")
    sig, err := base64.RawURLEncoding.DecodeString(parts[2])
    if err != nil {
        return nil, err
    }
    mac := hmac.New(sha256.New, []byte(secret))
    mac.Write([]byte(sigInput))
    if !hmac.Equal(sig, mac.Sum(nil)) {
        return nil, errors.New("sig")
    }
    payloadBytes, err := base64.RawURLEncoding.DecodeString(parts[1])
    if err != nil {
        return nil, err
    }
    var claims map[string]interface{}
    if err := json.Unmarshal(payloadBytes, &claims); err != nil {
        return nil, err
    }
    return claims, nil
}

// LRU-ish cache (tiny) to reduce auth calls
type cacheEntry struct {
    val       map[string]interface{}
    expiresAt time.Time
}

type LRUCache struct {
    items map[string]cacheEntry
    order []string
    max   int
    ttl   time.Duration
    mu    sync.Mutex
}

func NewLRUCache(max int, ttl time.Duration) *LRUCache {
    return &LRUCache{items: make(map[string]cacheEntry), order: make([]string, 0, max), max: max, ttl: ttl}
}

func (c *LRUCache) Get(key string) (map[string]interface{}, bool) {
    c.mu.Lock()
    defer c.mu.Unlock()
    ent, ok := c.items[key]
    if !ok || time.Now().After(ent.expiresAt) {
        delete(c.items, key)
        return nil, false
    }
    // move to end
    c.bump(key)
    return ent.val, true
}

func (c *LRUCache) Set(key string, val map[string]interface{}) {
    c.mu.Lock()
    defer c.mu.Unlock()
    if len(c.order) >= c.max {
        oldest := c.order[0]
        c.order = c.order[1:]
        delete(c.items, oldest)
    }
    c.items[key] = cacheEntry{val: val, expiresAt: time.Now().Add(c.ttl)}
    c.bump(key)
}

func (c *LRUCache) bump(key string) {
    // remove key if present
    for i, k := range c.order {
        if k == key {
            c.order = append(c.order[:i], c.order[i+1:]...)
            break
        }
    }
    c.order = append(c.order, key)
}

// Helpers
func getenv(key, def string) string {
    if v := strings.TrimSpace(strings.Trim(os.Getenv(key), "\"")); v != "" {
        return v
    }
    return def
}

func insecureTransport() *http.Transport {
    tr := &http.Transport{}
    tr.Proxy = http.ProxyFromEnvironment
    tr.TLSClientConfig = &tls.Config{InsecureSkipVerify: true}
    return tr
}
