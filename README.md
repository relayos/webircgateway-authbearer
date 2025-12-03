# AuthBearer plugin for Webircgateway

See kiwiirc/webircgateway https://github.com/kiwiirc/webircgateway

## Installation

```bash
# first clone webircgateway
git clone https://github.com/kiwiirc/webircgateway.git

# clone plugin
git clone https://github.com/nickautomatic/webircgateway-authbearer.git

# create folder for authbearer plugin
mkdir webircgateway/plugins/authbearer

# copy plugin files
cp webircgateway-authbearer/plugin.go webircgateway/plugins/authbearer/

# compile webircgateway with plugin
cd webircgateway && make
```

## Usage

Enable plugin in webircgateway config.conf:
```
[plugins]
plugins/authbearer.so
```

## Configuration

Environment variables:

| Variable | Default | Description |
|----------|---------|-------------|
| `WEBIRC_AUTHBEARER_ME_URL` | `https://bb.chat/oauth/me` | OAuth userinfo endpoint to validate tokens |
| `WEBIRC_AUTHBEARER_SHARED_SECRET` | (none) | Optional: accept HS256 signed id_tokens with this secret |
| `WEBIRC_AUTHBEARER_INSECURE` | `false` | Allow insecure TLS connections to auth endpoint |

## How it works

The plugin intercepts IRC connections and:

1. Extracts a bearer token from the client's `jwt` tag
2. Validates the token by calling the configured OAuth `/me` endpoint
3. Extracts username from claims (preferred_username, username, user_login, user_nicename, or email prefix)
4. Configures SASL PLAIN authentication upstream using the token as the password

This allows OAuth-authenticated web clients to transparently authenticate to IRC services that support token-based SASL.
