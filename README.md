# osv-mirror-worker

`osv-mirror-worker` is a small Cloudflare Worker that mirrors the OSV API endpoints used by Clawsec.

[![Deploy to Cloudflare](https://deploy.workers.cloudflare.com/button)](https://deploy.workers.cloudflare.com/?url=https://github.com/zweily/osv-mirror-worker)

Supported paths:

- `POST /v1/querybatch`
- `GET /v1/vulns/{id}`
- `GET /vulnerability/{id}`

It is intentionally not an open proxy. Requests outside those paths return `404`.

The `/vulnerability/{id}` route renders a human-readable advisory page on your mirror domain while `/v1/vulns/{id}` continues to return the raw OSV JSON payload.

## Use Case

If your endpoint environment cannot reach `https://api.osv.dev` directly but can reach a Cloudflare Worker domain, deploy this Worker and point Clawsec at it.

Examples:

```bash
clawsec scan --osv-base-url https://your-worker.workers.dev --no-open
```

```bash
clawsec report --database ./clawsec.sqlite3 --osv-base-url https://your-worker.workers.dev --no-open
```

Clawsec accepts either the Worker origin or an explicit `/v1` base.

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