# OpenID Connect for HFS

Log in to [HFS](https://github.com/rejetto/hfs) through Keycloak or another OpenID Connect provider. The provider handles the login screen, SSO and its configured MFA; HFS continues to control access to files through its accounts and groups.

Requires HFS plugin API 13.1 (HFS 3.2) and Node.js 20 or newer. HFS executables include their own Node.js runtime. The plugin uses HFS internal authentication functions through `api.require`; it needs no HFS modifications. The HFS 3.2 minimum is based on source compatibility; the real-provider tests described below ran on HFS 3.3.

## Installation

Copy `dist` into HFS's `plugins` directory and name the copied folder `openid-connect`. Enable **openid-connect** in Admin → Plugins, then open its options. All runtime dependencies are included; no npm installation is required on the HFS server.

## Configuration

1. Set **Issuer URL** to the provider's issuer, e.g. `https://sso.example.com/realms/my-realm`. Discovery is automatic; do not append `/.well-known/openid-configuration`.
2. Enter the **Client ID** and **Client secret** registered with the provider. Leave the secret empty for a public client. Confidential clients use `client_secret_post`.
3. Set **Public HFS URL** to the externally visible HTTPS address, including a proxy prefix if present: `https://files.example.com/` or `https://files.example.com/hfs/`.
4. Register this exact callback with the provider:

   ```text
   https://files.example.com/~/openid-connect/callback
   ```

   With the `/hfs/` prefix, it becomes `https://files.example.com/hfs/~/openid-connect/callback`.

5. Choose who can get an HFS account:
   - **Create accounts on first login** is off by default. Enable it to allow users authenticated by this provider to create accounts, optionally assigning **Groups for new accounts**. New usernames use **Username prefix** (default `oidc-`), followed by the `preferred_username` claim or the subject if unavailable. Leave the prefix empty to use the claim alone. Changing the prefix affects only new accounts; existing accounts keep their names and identity links. No local password is created.
   - **Link existing accounts** explicitly maps a subject (`sub`) from this issuer to an existing HFS account. To prepare an account without a password before its first OIDC login, create it as a **group** in HFS, configure its permissions, then select it here. Saving the mapping enables plugin authentication on that same account: no second account is created. Existing login methods and permissions are preserved. This also allows limiting access to selected identities while automatic creation stays off.
6. Reload the HFS frontend and open its login dialog. The **OpenID Connect** button starts the provider login. **Login button text** can give it a provider-specific label.

The issuer and all provider endpoints must use HTTPS. When HTTPS terminates at a reverse proxy, configure HFS's proxy support and forward the prefix as described in the [HFS reverse-proxy guide](https://github.com/rejetto/hfs/wiki/Reverse-proxy). The login button sends users to the configured public HFS address before starting authentication, so the session cookie is available at the callback even when the frontend was opened through another address.

## Keycloak example

Create an **OpenID Connect** client, for example `hfs`:

- Enable **Standard flow** (Authorization Code).
- Enable **Client authentication** for a confidential client and copy its secret into the plugin.
- Add the exact callback above under **Valid redirect URIs**.
- Require PKCE with **S256** if your Keycloak configuration exposes that setting. The plugin always sends PKCE.
- Ensure the client's `profile` scope includes `preferred_username` in the ID token if you want readable HFS usernames.

Use the realm URL as the issuer. In Keycloak, a user's ID is normally its OIDC `sub`; use that value for explicit account mappings. Configure MFA and any authentication policies in Keycloak.

## Identity and permissions

Automatically created accounts are bound to the exact `(issuer, sub)` pair, stored in their `plugin` metadata. Changing a display name or `preferred_username` does not move that identity to another account. A matching username or email never automatically links an existing local account. Name collisions are rejected; resolve them by renaming the conflicting account or making an explicit mapping.

Prepared accounts use the explicit mapping for authorization. If you rename one in HFS, update its mapping too. Before changing the issuer, remove or review all mappings: subjects belong to a particular provider and the same value at another provider can identify a different person. Removing the mapping prevents new OIDC logins to that prepared account; it does not invalidate existing sessions. The account retains its permissions and plugin-authentication marker. Keep automatic account creation off if only mapped identities should have access.

Groups are assigned at creation. Existing accounts keep their HFS permissions and group memberships; provider roles are not automatically imported. Disabled/expired accounts, inherited account restrictions and allowed networks are checked before login. HFS's login hooks still run. Local password login remains available for existing users.

The client secret is backend-only and uses a configuration key excluded by HFS's **export without passwords** option. Tokens and PKCE verifiers are not saved in HFS account data or browser cookies. Pending logins expire after five minutes, are bound to the initiating browser, and can be consumed only once. Restarting/reloading the plugin or changing its configuration cancels pending logins.

## Session and logout

After OIDC authentication, HFS creates its usual session. Its normal session duration applies, and the login dialog's **Allow IP change during this session** checkbox also applies to OIDC. HFS logout ends that HFS session; it does **not** end the provider session. Pressing the OIDC login button again may therefore sign you back in through SSO without another password prompt.

This version does not implement provider-initiated/back-channel logout or continuous provider-session checks. Disabling a user at the provider does not revoke an already-open HFS session. Disable the HFS account when immediate HFS access revocation is needed.

The button is part of the modern HFS frontend. Basic HTML login and WebDAV clients do not perform browser OIDC redirects; they can continue using the usual HFS authentication methods. An OIDC frontend login can access Admin only if that HFS account already has permission.

## Development

```sh
npm ci --no-audit
npm run build
npm test
```

The build bundles [openid-client](https://github.com/panva/openid-client) and its dependencies into `dist/openid-client.cjs`, including their license notices. Edit the handwritten plugin directly in `dist/plugin.js`; the build only regenerates the dependency bundle. Tests exercise the actual bundled OIDC client with signed tokens and simulated provider responses, plus HFS account/session stubs.

Also verified with a real local Keycloak 26.7.3 server, HFS 3.3.0-rc7 and Chromium on 2026-09-04: wrong-password rejection, Authorization Code + PKCE login, protected downloads, local HFS logout, SSO re-entry, TOTP enrollment and login, wrong-OTP rejection, login through an alternate HFS address, and the IP-change checkbox. Both servers used HTTPS with a temporary local certificate; HFS trusted that certificate through `NODE_EXTRA_CA_CERTS`. These browser tests used Keycloak's actual login forms and token endpoints, without intercepted provider responses.

The prepared-account flow was also verified against that real Keycloak server: creating an HFS group, setting permissions, saving its subject mapping, and logging in reused the same passwordless account without creating another account.

MIT license.
