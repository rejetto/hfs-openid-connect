const { test } = require('node:test')
const assert = require('node:assert/strict')
const { readFileSync } = require('node:fs')
const { runInNewContext } = require('node:vm')

test('login starts at the configured public origin and carries the IP-change checkbox', () => {
    let render, destination, checked = true
    runInNewContext(readFileSync(require.resolve('../dist/public/main.js'), 'utf8'), {
        URL,
        HFS: {
            prefixUrl: '/internal',
            getPluginConfig: () => ({ publicUrl: 'https://files.example/public' }),
            onEvent(name, callback) { assert.equal(name, 'beforeLogin'); render = callback },
            h: (tag, props, ...children) => ({ tag, props, children }),
        },
        document: { querySelector(selector) { assert.equal(selector, '#allow_session_ip_change input'); return { checked } } },
        location: { pathname: '/internal/folder/', origin: 'http://localhost', assign(url) { destination = new URL(url) } },
    })
    const button = render().children[0]
    assert.equal(button.props.type, 'button')
    button.props.onClick()
    assert.equal(destination.origin, 'https://files.example')
    assert.equal(destination.pathname, '/public/~/openid-connect/login')
    assert.equal(destination.searchParams.get('returnTo'), '/internal/folder/')
    assert.equal(destination.searchParams.get('allow_session_ip_change'), '1')
    checked = false
    button.props.onClick()
    assert.equal(destination.searchParams.has('allow_session_ip_change'), false)
})
