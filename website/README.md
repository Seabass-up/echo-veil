# Echo Veil product site

Public product page for [echo.algo-cli.com](https://echo.algo-cli.com). It is a
single-route vinext application deployed as a Cloudflare Worker with static
assets and a custom domain.

```bash
npm ci --ignore-scripts
npm run dev
npm run lint
npm test
```

`npm run deploy:cloudflare` builds and deploys the site to the configured
Cloudflare account and custom domain. Review the generated diff, security audit,
and live output before deploying. Do not add secrets to this directory.

The production Worker accepts only GET and HEAD and adds CSP, HSTS, framing,
MIME-sniffing, referrer, opener, and browser-permission policy to every route,
including image responses. The CSP permits the framework's generated inline
bootstrap and styles but blocks third-party scripts, objects, framing, and
off-origin connections.
