exports.version = 1
exports.description = "OpenID Connect login and SSO with Keycloak and other OIDC providers"
exports.apiRequired = 13.1
exports.repo = 'rejetto/hfs-openid-connect'
exports.frontend_js = 'main.js'
exports.configDialog = { sx: { maxWidth: 'min(600px, calc(100vw - 64px))' } }

exports.config = {
    issuer: { label: "Issuer URL", required: true,
        helperText: "For Keycloak: https://sso.example.com/realms/my-realm. Before changing provider, remove or review all existing account links." },
    clientId: { label: "Client ID", required: true, sm: 6 },
    _clientSecret: { label: "Client secret", sm: 6, inputProps: { type: 'password' }, helperText: "Leave empty for a public client" },
    publicUrl: { label: "Public HFS URL", required: true, frontend: true,
        helperText: "HTTPS address of HFS, including any proxy prefix, e.g. https://files.example.com/hfs/" },
    buttonLabel: { label: "Login button text", frontend: true, sm: 6, helperText: "Optional, e.g. Sign in with Keycloak" },
    usernamePrefix: { label: "Username prefix", defaultValue: 'oidc-', sm: 6,
        helperText: "For new accounts only. Leave empty for no prefix; existing accounts keep their names." },
    autoCreate: { label: "Create accounts on first login", type: 'boolean', defaultValue: false, sm: 6,
        helperText: "Allow any user authenticated by this provider to create an HFS account" },
    groups: { label: "Groups for new accounts", type: 'username', multiple: true, groups: true, defaultValue: [], sm: 6 },
    mappings: { label: "Link existing accounts", type: 'array', defaultValue: [],
        helperText: "Link a subject (sub) to an existing account. To prepare permissions before login, create an HFS group and select it here.",
        fields: { subject: { label: "Subject (sub)", required: true },
            username: { label: "HFS account", type: 'username', required: true } } },
}

exports.init = api => {
    if (Number(process.versions.node.split('.')[0]) < 20)
        throw Error("OpenID Connect requires Node.js 20 or newer")
    const oidc = require('./openid-client.cjs')
    const { setLoggedIn } = api.require('./auth')
    const { accountCanLogin, accountHasLoginMethod } = api.require('./perm')
    const { failAllowNet } = api.require('./middlewares')
    const { ALLOW_SESSION_IP_CHANGE } = api.Const
    const route = '/~/openid-connect/'
    const sessionKey = 'openid-connect:' + api.id
    const pending = new Map()
    let clientPromise
    let revision = 0
    api.subscribeConfig(Object.keys(exports.config), () => {
        // a changed provider or account policy must invalidate in-flight logins
        revision++
        clientPromise = undefined
        pending.clear()
        for (const mapping of api.getConfig('mappings')) {
            const account = api.getAccount(mapping.username)
            if (mapping.subject && account && !accountHasLoginMethod(account) && !account.plugin) {
                // do not persist subject here: removing a mapping must revoke access to this prepared account
                api.updateAccount(account, { plugin: { id: api.id, auth: true } })
                    .catch(() => api.log("Could not enable OpenID Connect for a linked account"))
            }
        }
    })
    api.setInterval(() => {
        for (const [state, transaction] of pending)
            if (transaction.expires <= Date.now()) pending.delete(state)
    }, 60_000)
    return { middleware }

    async function middleware(ctx) {
        if (ctx.path !== route + 'login' && ctx.path !== route + 'callback') return
        ctx.stop()
        // authorization codes from the callback do not belong in access logs
        ctx.state.safeUrl = ctx.path
        ctx.set('Cache-Control', 'no-store')
        ctx.set('Referrer-Policy', 'no-referrer')
        try {
            if (ctx.method !== 'GET') ctx.throw(405, "Use GET for OpenID Connect login")
            const base = publicBase()
            const redirectUri = new URL('.' + route + 'callback', base).href
            if (ctx.path === route + 'login') {
                const startedRevision = revision
                const client = await getClient()
                if (pending.size >= 1000) ctx.throw(503, "Too many pending logins; try again shortly")
                const state = oidc.randomState()
                const nonce = oidc.randomNonce()
                const verifier = oidc.randomPKCECodeVerifier()
                const challenge = await oidc.calculatePKCECodeChallenge(verifier)
                if (startedRevision !== revision) ctx.throw(400, "Configuration changed. Start login again.")
                // store secrets server-side: HFS session cookies are signed, not encrypted
                const binding = ctx.session[sessionKey] ||= oidc.randomState()
                pending.set(state, { binding, nonce, verifier, redirectUri, client, revision,
                    allowIpChange: ALLOW_SESSION_IP_CHANGE in ctx.query,
                    returnTo: returnPath(ctx.query.returnTo, base), expires: Date.now() + 300_000 })
                ctx.redirect(oidc.buildAuthorizationUrl(client, {
                    redirect_uri: redirectUri, scope: 'openid profile', state, nonce,
                    code_challenge: challenge, code_challenge_method: 'S256', response_mode: 'query',
                }).href)
            }
            else {
                const state = ctx.query.state
                const transaction = typeof state === 'string' && pending.get(state)
                if (!transaction || transaction.expires <= Date.now() || transaction.binding !== ctx.session[sessionKey])
                    ctx.throw(400, "Login expired or belongs to another browser. Start again from HFS.")
                // consume before exchanging the code so concurrent callbacks cannot reuse it
                pending.delete(state)
                const callback = new URL(transaction.redirectUri)
                callback.search = ctx.querystring
                const tokens = await oidc.authorizationCodeGrant(transaction.client, callback, {
                    expectedState: state, expectedNonce: transaction.nonce,
                    pkceCodeVerifier: transaction.verifier, idTokenExpected: true,
                })
                if (transaction.revision !== revision) ctx.throw(400, "Configuration changed. Start login again.")
                // preserve the option chosen before leaving HFS, not flags injected into the callback
                delete ctx.query[ALLOW_SESSION_IP_CHANGE]
                ctx.state.params = { ...ctx.state.params, [ALLOW_SESSION_IP_CHANGE]: transaction.allowIpChange }
                const account = await resolveAccount(tokens.claims())
                if (!account || !accountCanLogin(account) || failAllowNet(ctx, account))
                    ctx.throw(403, "This account is not allowed to log in to HFS.")
                if ((await api.events.emitAsync('attemptingLogin', { ctx, username: account.username, via: 'openid-connect' }))?.isDefaultPrevented())
                    ctx.throw(403, "Login was blocked by an HFS plugin.")
                if (transaction.revision !== revision) ctx.throw(400, "Configuration changed. Start login again.")
                // setLoggedIn sets ctx.state.account before hooks can reject the login
                try { await setLoggedIn(ctx, account.username) }
                catch (error) {
                    await setLoggedIn(ctx, false)
                    throw error
                }
                ctx.redirect(transaction.returnTo)
            }
        }
        catch (error) {
            // provider errors can contain tokens or secrets; only log their diagnostic code
            api.log("OpenID Connect login failed:", error.code || error.name || 'login rejected')
            ctx.status = error.status || 401
            ctx.type = 'text/plain'
            ctx.body = error.expose ? error.message : "OpenID Connect login failed. Return to HFS and try again, or contact the administrator."
        }
    }

    function publicBase() {
        const url = new URL(api.getConfig('publicUrl'))
        if (url.protocol !== 'https:' || url.username || url.password || url.search || url.hash)
            throw Error("Public HFS URL must be HTTPS without credentials, query or fragment")
        url.pathname = url.pathname.replace(/\/?$/, '/')
        return url
    }

    function returnPath(value, base) {
        const url = new URL(typeof value === 'string' ? value : base.pathname, base)
        // return only to a folder within this HFS installation, never an external site
        return url.origin === base.origin && url.pathname.startsWith(base.pathname)
            ? url.origin + url.pathname : base.href
    }

    function getClient() {
        if (!clientPromise) {
            clientPromise = oidc.discovery(new URL(api.getConfig('issuer')), api.getConfig('clientId'),
                api.getConfig('_clientSecret') || undefined, undefined,
                { execute: [oidc.enableNonRepudiationChecks], timeout: 10 })
            clientPromise.catch(() => { clientPromise = undefined })
        }
        return clientPromise
    }

    async function resolveAccount(claims) {
        if (!claims.sub) throw Error("The provider returned an empty subject")
        const mapping = api.getConfig('mappings').find(x => x.subject === claims.sub)
        if (mapping) return api.getAccount(mapping.username)
        const account = api.getUsernames().map(u => api.getAccount(u)).find(a =>
            a.plugin?.id === api.id && a.plugin.issuer === claims.iss && a.plugin.subject === claims.sub)
        if (account) return account
        if (!api.getConfig('autoCreate')) return
        const name = api.getConfig('usernamePrefix') + (claims.preferred_username || claims.sub)
        // never attach a new identity to an existing local account on a name match
        if (api.getAccount(name)) return
        return api.addAccount(name, {
            belongs: api.getConfig('groups'), disable_password_change: true,
            plugin: { id: api.id, auth: true, issuer: claims.iss, subject: claims.sub },
        })
    }
}
