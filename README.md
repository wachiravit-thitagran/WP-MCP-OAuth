# WP MCP OAuth

OAuth 2.1 authorization layer for WordPress MCP endpoints.

This plugin lets ChatGPT authenticate to a WordPress MCP server without receiving a WordPress Application Password. It adds OAuth discovery, Authorization Code + PKCE, opaque access/refresh tokens, consent, bearer authentication, scope boundaries, and WordPress user mapping in front of the WordPress MCP Adapter.

## Requirements

- WordPress 6.9+
- PHP 7.4+
- WordPress MCP Adapter
- HTTPS

Default protected MCP resource:

```text
/wp-json/mcp/mcp-adapter-default-server
```

## OAuth endpoints

```text
/.well-known/oauth-protected-resource
/.well-known/oauth-authorization-server
/oauth/authorize
/oauth/token
/oauth/revoke
```

The authorization server supports:

- OAuth Authorization Code flow
- PKCE S256
- Client ID Metadata Documents (CIMD) for ChatGPT
- RFC 8707-style resource binding
- issuer identification in authorization responses
- opaque access tokens
- rotating refresh tokens
- token revocation

## ChatGPT client support

The plugin currently allows OpenAI-managed ChatGPT CIMD clients:

```text
https://chatgpt.com/oauth/client.json
```

with the stable callback:

```text
https://chatgpt.com/connector_platform_oauth_redirect
```

It also accepts the callback-specific ChatGPT CIMD form and requires the callback identifier in the client metadata URL and redirect URL to match.

## Scopes

```text
wordpress:read
wordpress:write
wordpress:admin
```

Scopes reduce the WordPress user's effective capabilities. They do not grant capabilities that the user does not already have.

- `wordpress:read`: read-only WordPress/Tutor LMS access
- `wordpress:write`: content/media mutation, subject to WordPress capabilities
- `wordpress:admin`: administrative operations such as plugin updates, user administration, options, cache, cron, and database maintenance

WordPress capabilities remain the final authorization layer.

## Token model

Access tokens are opaque random values and are stored only as SHA-256 hashes.

Default lifetimes:

```text
Authorization code: 5 minutes
Access token:      1 hour
Refresh token:     30 days
```

Refresh tokens are rotated on use.

## Installation

Upload the release ZIP from GitHub:

```text
Plugins
→ Add Plugin
→ Upload Plugin
→ wp-mcp-oauth-<version>.zip
→ Activate
```

Activation creates:

```text
wp_mcp_oauth_codes
wp_mcp_oauth_tokens
```

using the site's configured WordPress table prefix.

## ChatGPT connection

Create a custom MCP server in ChatGPT using:

```text
https://YOUR-WORDPRESS-SITE/wp-json/mcp/mcp-adapter-default-server
```

Choose OAuth authentication and CIMD.

When linking the account, ChatGPT discovers this site's protected-resource metadata, opens the WordPress authorization page, and receives a bearer token after the logged-in WordPress user approves access.

## Existing Application Passwords

This plugin does not disable WordPress Application Password authentication. Existing tools can continue to use Application Passwords while ChatGPT uses OAuth bearer tokens.

## Security model

- Authorization codes are single-use and expire after five minutes.
- PKCE `S256` is mandatory.
- Every authorization and token request is bound to the exact MCP resource URL.
- Redirect URIs are restricted to supported ChatGPT callback patterns.
- Access and refresh tokens are stored only as hashes.
- Bearer tokens map back to a WordPress user.
- OAuth scopes only reduce permissions; they never add WordPress capabilities.
- Administrative capabilities are removed unless the token contains `wordpress:admin`.
- Content mutation capabilities are removed unless the token contains `wordpress:write` or `wordpress:admin`.
- The MCP endpoint returns a bearer challenge advertising protected-resource metadata when OAuth authentication is required.

## Architecture

```text
ChatGPT
   │ OAuth 2.1 + PKCE
   ▼
WP MCP OAuth
   │ Bearer token → WordPress user
   ▼
WordPress MCP Adapter
   ▼
WordPress Abilities API
   ├── WP-Ability
   ├── Tutor LMS abilities
   └── other ability providers
```

## License

GPL-2.0-or-later
