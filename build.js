const { build } = require('esbuild')
const { readFileSync, writeFileSync } = require('node:fs')

build({
    stdin: { contents: "export * from 'openid-client'", resolveDir: __dirname },
    bundle: true, platform: 'node', target: 'node20', format: 'cjs',
    outfile: 'dist/openid-client.cjs', minify: true, legalComments: 'eof',
}).catch(() => { process.exitCode = 1 })
writeFileSync('dist/THIRD-PARTY-LICENSES.txt', ['openid-client', 'oauth4webapi', 'jose'].map(name =>
    name + '\n\n' + readFileSync(`node_modules/${name}/LICENSE.md`, 'utf8')).join('\n\n'))
