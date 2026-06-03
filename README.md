# osv-mirror-worker

[中文](README.zh-CN.md)

`osv-mirror-worker` is a small Cloudflare Worker that mirrors the OSV API endpoints used by [Clawsec](https://github.com/zweily/clawsec).

[![Deploy to Cloudflare](https://deploy.workers.cloudflare.com/button)](https://deploy.workers.cloudflare.com/?url=https://github.com/zweily/osv-mirror-worker)

Supported paths:

- `POST /v1/querybatch`
- `GET /v1/vulns/{id}`
- `GET /vulnerability/{id}`

It is intentionally not an open proxy. Requests outside those paths return `404`.

The `/vulnerability/{id}` route renders a human-readable advisory page on your mirror domain while `/v1/vulns/{id}` continues to return the raw OSV JSON payload.

## Use Case

If your endpoint environment cannot reach `https://api.osv.dev` directly but can reach a Cloudflare Worker domain, deploy this Worker and point [Clawsec](https://github.com/zweily/clawsec) at it.

Examples:

```bash
clawsec scan --osv-base-url https://your-worker.workers.dev --no-open
```

```bash
clawsec report --database ./clawsec.sqlite3 --osv-base-url https://your-worker.workers.dev --no-open
```

[Clawsec](https://github.com/zweily/clawsec) accepts either the Worker origin or an explicit `/v1` base.

When you use `--osv-base-url` during `clawsec scan` or `clawsec report`, OSV-backed report links now point to the mirror-hosted `/vulnerability/{id}` page instead of the raw JSON endpoint.

## Setup

Install dependencies:

```bash
npm install
```

Authenticate Wrangler if needed:

```bash
npx wrangler login
```

Run locally:

```bash
npm run dev
```

Type-check the Worker:

```bash
npm run check
```

Run the automated tests:

```bash
npm test
```

Deploy:

```bash
npm run deploy
```

## Configuration

`wrangler.toml` includes a default upstream:

```toml
[vars]
OSV_ORIGIN = "https://api.osv.dev"
```

If you want the Worker to target a different OSV-compatible upstream later, change that variable and redeploy.

## Security And Operations

- The Worker forwards only the upstream headers it actually needs instead of proxying client `Authorization`, `Cookie`, or other ambient headers.
- Successful `GET /v1/vulns/{id}` and `GET /vulnerability/{id}` responses are cached briefly to reduce latency and upstream load.
- Open CORS is intentional so browser-based tools can call the mirror directly.
- For public deployments, configure Cloudflare rate limiting rules at the zone or route level if you expect shared or untrusted traffic.
- Prefer stricter Cloudflare rate limits on `POST /v1/querybatch` than on the cached `GET` routes.
- Consider Cloudflare WAF or Custom Rules to block malformed paths, abusive methods, or suspicious request patterns before they hit the Worker.
- Consider Cloudflare Cache Rules if you want stronger edge-cache controls than the Worker response headers alone provide.
- If the service should only be reachable by a controlled team or environment, use Cloudflare Access instead of leaving the mirror fully public.
- If a public deployment starts attracting scraping or bot traffic, evaluate Cloudflare Bot Management or Super Bot Fight Mode.
- Local secret files such as `.dev.vars` and `.env*` are gitignored.

## License

This project is released under the MIT License. See `LICENSE`.