'use strict';{
    const { publicUrl, buttonLabel } = HFS.getPluginConfig()
    if (publicUrl) HFS.onEvent('beforeLogin', () => HFS.h('div', { className: 'field' },
        HFS.h('button', {
            type: 'button',
            onClick() {
                // start on the callback origin so HFS reads the same host/protocol session cookie
                const url = new URL('~/openid-connect/login', publicUrl.replace(/\/?$/, '/'))
                url.searchParams.set('returnTo', location.pathname)
                const key = 'allow_session_ip_change'
                if (document.querySelector('#' + key + ' input')?.checked) url.searchParams.set(key, '1')
                location.assign(url.href)
            },
        }, buttonLabel || "OpenID Connect")))
}
