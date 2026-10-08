'use strict';{
    const { buttonLabel } = HFS.getPluginConfig()
    HFS.onEvent('beforeLogin', () => HFS.h('div', { className: 'field' },
        HFS.h('button', {
            type: 'button',
            onClick() {
                const url = new URL(HFS.prefixUrl + '/~/openid-connect/login', location.origin)
                url.searchParams.set('returnTo', location.pathname.slice(HFS.prefixUrl.length))
                const key = 'allow_session_ip_change'
                if (document.querySelector('#' + key + ' input')?.checked) url.searchParams.set(key, '1')
                location.assign(url.href)
            },
        }, buttonLabel || "OpenID Connect")))
}
