const { test } = require('node:test')
const assert = require('node:assert/strict')
const { generateKeyPairSync, sign, createHash } = require('node:crypto')
const plugin = require('../dist/plugin')

test('OIDC authorization code flow and HFS account boundaries', async t => {
    const { privateKey, publicKey } = generateKeyPairSync('rsa', { modulusLength: 2048 })
    const issuer = 'https://identity.example/realms/test'
    const jwk = { ...publicKey.export({ format: 'jwk' }), kid: 'test', alg: 'RS256', use: 'sig' }
    const codes = new Map()
    const originalFetch = global.fetch
    t.after(() => { global.fetch = originalFetch })
    let tokenRequests = 0
    global.fetch = async (input, options) => {
        const url = new URL(input)
        if (url.href === issuer + '/.well-known/openid-configuration') return json({
            issuer, authorization_endpoint: issuer + '/auth', token_endpoint: issuer + '/token',
            jwks_uri: issuer + '/keys', response_types_supported: ['code'],
            subject_types_supported: ['public'], id_token_signing_alg_values_supported: ['RS256'],
            code_challenge_methods_supported: ['S256'],
        })
        if (url.href === issuer + '/keys') return json({ keys: [jwk] })
        assert.equal(url.href, issuer + '/token')
        tokenRequests++
        const params = new URLSearchParams(options.body)
        const data = codes.get(params.get('code'))
        assert.ok(data, 'authorization code must be registered')
        assert.equal(params.get('client_id'), 'hfs')
        assert.equal(params.get('client_secret'), 'secret')
        assert.equal(params.get('redirect_uri'), data.redirectUri)
        assert.equal(createHash('sha256').update(params.get('code_verifier')).digest('base64url'), data.challenge)
        const now = Math.floor(Date.now() / 1000)
        const claims = { iss: issuer, sub: 'user-123', aud: 'hfs', iat: now, exp: now + 300,
            nonce: data.nonce, preferred_username: 'alice', ...data.claims }
        const unsigned = encode({ alg: 'RS256', kid: 'test' }) + '.' + encode(claims)
        const signature = sign('RSA-SHA256', Buffer.from(unsigned), privateKey).toString('base64url')
        return json({ access_token: 'unused', token_type: 'Bearer',
            id_token: unsigned + '.' + (data.badSignature ? 'AAAA' : signature) })
    }

    await t.test('creates an account, opens a session, and preserves its identity across renamed claims', async () => {
        const h = harness()
        const login = await start(h)
        const callback = await finish(h, login)
        assert.equal(callback.status, 302)
        assert.equal(callback.location, 'https://files.example/prefix/folder/')
        assert.equal(login.session.username, 'oidc-alice')
        assert.deepEqual(h.accounts.get('oidc-alice').plugin, { id: 'openid-connect', auth: true, issuer, subject: 'user-123' })
        const again = await start(h)
        await finish(h, again, { preferred_username: 'renamed' })
        assert.equal(again.session.username, 'oidc-alice')
        assert.equal(h.accounts.size, 1)
        const replay = await h.request('/callback', callback.querystring, login.session)
        assert.equal(replay.status, 400)
    })
    await t.test('supports custom and empty prefixes, preserving existing identities and rejecting collisions', async () => {
        for (const usernamePrefix of ['sso-', '']) {
            const h = harness({ usernamePrefix })
            const login = await start(h)
            assert.equal((await finish(h, login)).status, 302)
            assert.equal(login.session.username, usernamePrefix + 'alice')
            h.config.usernamePrefix = 'changed-'
            h.changed()
            const again = await start(h)
            assert.equal((await finish(h, again)).status, 302)
            assert.equal(again.session.username, usernamePrefix + 'alice')
            assert.equal(h.accounts.size, 1)

            const collision = harness({ usernamePrefix })
            const local = { username: usernamePrefix + 'alice', srp: 'local-password' }
            collision.accounts.set(local.username, local)
            assert.equal((await finish(collision, await start(collision))).status, 403)
            assert.equal(local.plugin, undefined)
        }
    })
    await t.test('binds callback to browser and checks state before token exchange', async () => {
        const h = harness()
        const login = await start(h)
        const before = tokenRequests
        const wrongBrowser = await h.request('/callback', 'state=' + login.state + '&code=x', {})
        assert.equal(wrongBrowser.status, 400)
        const wrongState = await h.request('/callback', 'state=wrong&code=x', login.session)
        assert.equal(wrongState.status, 400)
        assert.equal(tokenRequests, before)
        assert.equal((await finish(h, login)).status, 302)
    })
    for (const [name, claims] of Object.entries({ nonce: { nonce: 'wrong' }, audience: { aud: 'other' },
        issuer: { iss: 'https://other.example' }, expiry: { exp: 1 }, subject: { sub: '' } })) {
        await t.test('rejects invalid ' + name, async () => {
            const h = harness()
            const login = await start(h)
            assert.equal((await finish(h, login, claims)).status, 401)
            assert.equal(h.accounts.size, 0)
            assert.equal(login.session.username, undefined)
        })
    }
    await t.test('rejects invalid signatures', async () => {
        const h = harness()
        const login = await start(h)
        assert.equal((await finish(h, login, {}, true)).status, 401)
        assert.equal(h.accounts.size, 0)
    })
    await t.test('does not link matching local names and requires opt-in for provisioning', async () => {
        const h = harness({ autoCreate: false })
        assert.equal((await finish(h, await start(h))).status, 403)
        h.config.autoCreate = true
        h.accounts.set('oidc-alice', { username: 'oidc-alice', srp: 'local-password' })
        assert.equal((await finish(h, await start(h))).status, 403)
        assert.equal(h.accounts.get('oidc-alice').plugin, undefined)
    })
    await t.test('explicit mappings preserve HFS account, network, and plugin restrictions', async () => {
        const h = harness({ mappings: [{ subject: 'user-123', username: 'local' }] })
        const account = { username: 'local', srp: 'password' }
        h.accounts.set('local', account)
        assert.equal((await finish(h, await start(h))).status, 302)
        for (const field of ['disabled', 'expired', 'denyNetwork']) {
            account[field] = true
            const login = await start(h)
            assert.equal((await finish(h, login)).status, 403)
            assert.equal(login.session.username, undefined)
            delete account[field]
        }
        h.blockLogin = true
        assert.equal((await finish(h, await start(h))).status, 403)
        h.blockLogin = false
        h.rejectFinalizing = true
        const login = await start(h)
        const callback = await finish(h, login)
        assert.equal(callback.status, 401)
        assert.equal(callback.state.account, undefined)
        assert.equal(callback.session, null)
    })
    await t.test('prepares a passwordless account without duplication and requires its explicit mapping', async () => {
        const h = harness({ autoCreate: false })
        const account = { username: 'prepared', belongs: ['staff'], notes: 'Permissions prepared in advance' }
        h.accounts.set(account.username, account)
        h.config.mappings = [{ subject: 'user-123', username: account.username }]
        h.changed()
        assert.deepEqual(account.plugin, { id: 'openid-connect', auth: true })
        assert.equal(account.srp, undefined)
        const login = await start(h)
        assert.equal((await finish(h, login)).status, 302)
        assert.equal(login.session.username, 'prepared')
        assert.equal(h.accounts.size, 1)
        assert.deepEqual(account.belongs, ['staff'])
        assert.equal(account.notes, 'Permissions prepared in advance')
        account.disabled = true
        assert.equal((await finish(h, await start(h))).status, 403)
        delete account.disabled
        h.config.mappings = []
        h.changed()
        assert.equal((await finish(h, await start(h))).status, 403)
        assert.equal(h.accounts.size, 1)
    })
    await t.test('configuration changes and expired transactions cancel pending logins', async () => {
        const h = harness()
        const login = await start(h)
        h.changed()
        assert.equal((await finish(h, login)).status, 400)
        const expired = await start(h)
        const realNow = Date.now
        try {
            Date.now = () => realNow() + 360_000
            assert.equal((await finish(h, expired)).status, 400)
        }
        finally { Date.now = realNow }
    })
    await t.test('blocks external return redirects and rejects non-GET callbacks', async () => {
        const h = harness()
        for (const path of ['https://evil.example/', '//evil.example/', '/outside/']) {
            const login = await start(h, path)
            assert.equal((await finish(h, login)).location, 'https://files.example/prefix/')
        }
        assert.equal((await h.request('/callback', '', {}, 'POST')).status, 405)
    })
    await t.test('a double-slash path cannot turn a same-origin return URL into an external redirect', async () => {
        const h = harness({ publicUrl: 'https://files.example/' })
        const login = await start(h, 'https://files.example//example.invalid/path')
        const callback = await finish(h, login)
        assert.equal(new URL(callback.location).origin, 'https://files.example')
    })
    await t.test('carries the chosen IP-change option and ignores flags injected into the callback', async () => {
        const h = harness()
        const allowed = await start(h, undefined, true)
        assert.equal((await finish(h, allowed)).status, 302)
        assert.equal(allowed.session.allow_session_ip_change, true)
        const restricted = await start(h)
        assert.equal((await finish(h, restricted, {}, false, { allow_session_ip_change: '1' })).status, 302)
        assert.equal(restricted.session.allow_session_ip_change, false)
    })

    function harness(overrides = {}) {
        const config = { ...Object.fromEntries(Object.entries(plugin.config).map(([k, v]) => [k, v.defaultValue])),
            issuer, clientId: 'hfs', _clientSecret: 'secret', publicUrl: 'https://files.example/prefix/', autoCreate: true, ...overrides }
        const accounts = new Map()
        const h = { config, accounts }
        const internal = {
            async setLoggedIn(ctx, username) {
                if (username === false) { ctx.session = null; delete ctx.state.account; return }
                ctx.state.account = accounts.get(username)
                if (h.rejectFinalizing) throw Error('hook rejected')
                ctx.session.username = username
                ctx.session.allow_session_ip_change = 'allow_session_ip_change' in ctx.query || ctx.state.params.allow_session_ip_change
            },
            accountCanLogin: a => !a.disabled && !a.expired && Boolean(a.srp || a.plugin?.auth),
            accountHasLoginMethod: a => Boolean(a.password || a.srp || a.plugin?.auth || a.auto_login_net),
            failAllowNet: (ctx, a) => a.denyNetwork,
        }
        const modules = { './auth': internal, './perm': internal, './middlewares': internal }
        const initialized = plugin.init({ id: 'openid-connect', require: path => {
            assert.ok(path in modules)
            return modules[path]
        }, Const: { ALLOW_SESSION_IP_CHANGE: 'allow_session_ip_change' },
            getConfig: k => config[k], getAccount: name => accounts.get(name), getUsernames: () => [...accounts.keys()],
            async updateAccount(account, changes) { Object.assign(account, changes) },
            async addAccount(username, properties) {
                const a = { username: username.toLowerCase(), ...properties }
                if (accounts.has(a.username)) return
                accounts.set(a.username, a)
                return a
            },
            subscribeConfig(keys, callback) { h.changed = callback; callback() },
            setInterval() {}, log() {}, events: { emitAsync: async () => ({ isDefaultPrevented: () => h.blockLogin }) },
        })
        h.request = async (path, querystring = '', session = {}, method = 'GET') => {
            const ctx = { path: '/~/openid-connect' + path, querystring, query: Object.fromEntries(new URLSearchParams(querystring)),
                session, method, state: { params: false }, headers: {}, status: 404,
                stop() { this.stopped = true }, set(k, v) { this.headers[k] = v },
                redirect(url) { this.location = url; this.status = 302 },
                throw(status, message) { throw Object.assign(Error(message), { status, expose: true }) } }
            await initialized.middleware(ctx)
            return ctx
        }
        return h
    }

    async function start(h, path = '/prefix/folder/', allowIpChange = false) {
        const ctx = await h.request('/login', 'returnTo=' + encodeURIComponent(path)
            + (allowIpChange ? '&allow_session_ip_change=1' : ''))
        assert.equal(ctx.status, 302, ctx.body)
        assert.equal(ctx.headers['Cache-Control'], 'no-store')
        const url = new URL(ctx.location)
        assert.equal(url.searchParams.get('code_challenge_method'), 'S256')
        return { session: ctx.session, state: url.searchParams.get('state'),
            nonce: url.searchParams.get('nonce'), challenge: url.searchParams.get('code_challenge'),
            redirectUri: url.searchParams.get('redirect_uri') }
    }

    async function finish(h, login, claims = {}, badSignature = false, query = {}) {
        const code = 'code-' + codes.size
        codes.set(code, { ...login, claims, badSignature })
        return h.request('/callback', new URLSearchParams({ state: login.state, code, ...query }).toString(), login.session)
    }

    function json(value) { return new Response(JSON.stringify(value), { headers: { 'content-type': 'application/json' } }) }
    function encode(value) { return Buffer.from(JSON.stringify(value)).toString('base64url') }
})
