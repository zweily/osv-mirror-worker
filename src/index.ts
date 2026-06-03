export interface Env {
  OSV_ORIGIN?: string;
}

const DEFAULT_OSV_ORIGIN = "https://api.osv.dev";
const SUPPORTED_PATHS = ["POST /v1/querybatch", "GET /v1/vulns/{id}", "GET /vulnerability/{id}"];
export const MAX_QUERYBATCH_BYTES = 1_048_576;
export const MAX_QUERYBATCH_QUERIES = 100;
export const MAX_VULNERABILITY_ID_LENGTH = 256;
export const UPSTREAM_FETCH_TIMEOUT_MS = 8_000;
const EDGE_CACHE_MAX_AGE_SECONDS = 300;
const BROWSER_CACHE_MAX_AGE_SECONDS = 60;
const FORWARDED_UPSTREAM_HEADER_NAMES = ["accept", "content-type"] as const;

type RequestBodyReadResult =
  | { ok: true; body: Uint8Array }
  | { ok: false; status: 400 | 413; error: string };

type QueryBatchValidationResult =
  | { ok: true; body: string }
  | {
      ok: false;
      status: 400 | 413 | 415;
      error: string;
      maxQueries?: number;
    };

interface OsvSeverity {
  type?: string;
  score?: string;
}

interface OsvReference {
  type?: string;
  url?: string;
}

interface OsvPackage {
  ecosystem?: string;
  name?: string;
  purl?: string;
}

interface OsvRangeEvent {
  introduced?: string;
  fixed?: string;
  last_affected?: string;
  limit?: string;
}

interface OsvAffectedRange {
  type?: string;
  repo?: string;
  events?: OsvRangeEvent[];
}

interface OsvAffectedPackage {
  package?: OsvPackage;
  versions?: string[];
  ranges?: OsvAffectedRange[];
}

interface OsvVulnerability {
  id: string;
  aliases?: string[];
  summary?: string;
  details?: string;
  published?: string;
  modified?: string;
  withdrawn?: string;
  severity?: OsvSeverity[];
  references?: OsvReference[];
  affected?: OsvAffectedPackage[];
}

class UpstreamTimeoutError extends Error {
  constructor() {
    super("Upstream OSV request timed out");
    this.name = "UpstreamTimeoutError";
  }
}

export default {
  async fetch(request: Request, env: Env, ctx: ExecutionContext): Promise<Response> {
    const url = new URL(request.url);
    const supportedApiPath = isSupportedApiPath(url.pathname, request.method);

    if (request.method === "OPTIONS") {
      return withCors(new Response(null, { status: 204 }));
    }

    if (request.method === "GET" && (url.pathname === "/" || url.pathname === "/healthz")) {
      return json(
        {
          name: "osv-mirror-worker",
          status: "ok",
          upstream: normalizeOrigin(env.OSV_ORIGIN),
          supportedPaths: SUPPORTED_PATHS,
        },
        200,
      );
    }

    const vulnerabilityPageId = getVulnerabilityPageId(url.pathname);
    if (url.searchParams.size > 0 && (supportedApiPath || vulnerabilityPageId)) {
      return json(
        {
          error: "Query parameters are not supported on this route",
        },
        400,
      );
    }

    if (request.method === "GET" && vulnerabilityPageId) {
      return serveVulnerabilityPage(url, env, vulnerabilityPageId, ctx);
    }

    if (!supportedApiPath) {
      return json(
        {
          error: "Unsupported path",
          supportedPaths: SUPPORTED_PATHS,
        },
        404,
      );
    }

    const cacheKey = getApiCacheKey(url, request.method);
    if (cacheKey) {
      const cachedResponse = await caches.default.match(cacheKey);
      if (cachedResponse) {
        return cachedResponse;
      }
    }

    let requestBody: string | undefined;
    if (request.method === "POST") {
      if (!isJsonContentType(request.headers.get("content-type"))) {
        return json(
          {
            error: "Content-Type must be application/json",
          },
          415,
        );
      }

      const bodyResult = await readRequestBodyWithinLimit(request, MAX_QUERYBATCH_BYTES);
      if (!bodyResult.ok) {
        return json(
          {
            error: bodyResult.error,
            maxBytes: MAX_QUERYBATCH_BYTES,
          },
          bodyResult.status,
        );
      }

      const queryBatchResult = validateQueryBatchPayload(bodyResult.body);
      if (!queryBatchResult.ok) {
        return json(
          {
            error: queryBatchResult.error,
            ...(queryBatchResult.maxQueries
              ? {
                  maxQueries: queryBatchResult.maxQueries,
                }
              : {}),
          },
          queryBatchResult.status,
        );
      }

      requestBody = queryBatchResult.body;
    }

    const upstreamUrl = `${normalizeOrigin(env.OSV_ORIGIN)}${url.pathname}${url.search}`;
    const headers = buildUpstreamHeaders(request, url);

    try {
      const upstreamResponse = await fetchUpstreamWithTimeout(upstreamUrl, {
        method: request.method,
        headers,
        body: requestBody,
        redirect: "follow",
      });

      const responseHeaders = new Headers(upstreamResponse.headers);
      responseHeaders.delete("set-cookie");
      responseHeaders.set("x-proxied-by", "osv-mirror-worker");
      if (cacheKey && upstreamResponse.ok) {
        applyPublicCacheHeaders(responseHeaders);
      }
      applyCors(responseHeaders);

      const response = new Response(upstreamResponse.body, {
        status: upstreamResponse.status,
        statusText: upstreamResponse.statusText,
        headers: responseHeaders,
      });

      if (cacheKey && upstreamResponse.ok) {
        ctx.waitUntil(caches.default.put(cacheKey, response.clone()));
      }

      return response;
    } catch (error) {
      return json(
        {
          error: error instanceof UpstreamTimeoutError ? error.message : "Upstream OSV request failed",
          details: error instanceof Error ? error.message : "Unknown error",
        },
        error instanceof UpstreamTimeoutError ? 504 : 502,
      );
    }
  },
} satisfies ExportedHandler<Env>;

export function isSupportedApiPath(pathname: string, method: string): boolean {
  if (pathname === "/v1/querybatch") {
    return method === "POST";
  }

  if (pathname.startsWith("/v1/vulns/")) {
    const suffix = pathname.slice("/v1/vulns/".length);
    return method === "GET" && parseVulnerabilityIdSegment(suffix) !== null;
  }

  return false;
}

export function getVulnerabilityPageId(pathname: string): string | null {
  if (!pathname.startsWith("/vulnerability/")) {
    return null;
  }

  const suffix = pathname.slice("/vulnerability/".length);
  return parseVulnerabilityIdSegment(suffix);
}

function parseVulnerabilityIdSegment(value: string): string | null {
  if (!value || value.includes("/")) {
    return null;
  }

  try {
    const decoded = decodeURIComponent(value);
    if (!decoded || decoded.includes("/") || decoded.length > MAX_VULNERABILITY_ID_LENGTH) {
      return null;
    }
    return decoded;
  } catch {
    return null;
  }
}

function normalizeOrigin(origin: string | undefined): string {
  const value = origin?.trim().replace(/\/+$/, "");
  if (!value) {
    return DEFAULT_OSV_ORIGIN;
  }
  return value;
}

function getApiCacheKey(url: URL, method: string): Request | null {
  if (method !== "GET" || !isSupportedApiPath(url.pathname, method)) {
    return null;
  }

  return new Request(`${url.origin}${url.pathname}`, { method: "GET" });
}

function isJsonContentType(contentType: string | null): boolean {
  if (!contentType) {
    return false;
  }

  const mediaType = contentType.split(";", 1)[0]?.trim().toLowerCase();
  return mediaType === "application/json";
}

function validateQueryBatchPayload(body: Uint8Array): QueryBatchValidationResult {
  let decoded: string;
  try {
    decoded = new TextDecoder("utf-8", { fatal: true, ignoreBOM: false }).decode(body);
  } catch {
    return {
      ok: false,
      status: 400,
      error: "Request body must be valid UTF-8 JSON",
    };
  }

  let payload: unknown;
  try {
    payload = JSON.parse(decoded);
  } catch {
    return {
      ok: false,
      status: 400,
      error: "Request body must be valid JSON",
    };
  }

  if (!payload || typeof payload !== "object" || Array.isArray(payload)) {
    return {
      ok: false,
      status: 400,
      error: "querybatch body must be a JSON object",
    };
  }

  const queries = (payload as Record<string, unknown>).queries;
  if (!Array.isArray(queries)) {
    return {
      ok: false,
      status: 400,
      error: "querybatch body must include a queries array",
    };
  }

  if (queries.length === 0) {
    return {
      ok: false,
      status: 400,
      error: "queries array must not be empty",
    };
  }

  if (queries.length > MAX_QUERYBATCH_QUERIES) {
    return {
      ok: false,
      status: 413,
      error: "Too many queries in batch",
      maxQueries: MAX_QUERYBATCH_QUERIES,
    };
  }

  if (queries.some((query) => !query || typeof query !== "object" || Array.isArray(query))) {
    return {
      ok: false,
      status: 400,
      error: "Each query must be a JSON object",
    };
  }

  return {
    ok: true,
    body: JSON.stringify(payload),
  };
}

async function fetchUpstreamWithTimeout(input: string, init: RequestInit): Promise<Response> {
  const controller = new AbortController();
  let timedOut = false;
  const timeoutId = setTimeout(() => {
    timedOut = true;
    controller.abort();
  }, UPSTREAM_FETCH_TIMEOUT_MS);

  try {
    return await fetch(input, {
      ...init,
      signal: controller.signal,
    });
  } catch (error) {
    if (timedOut) {
      throw new UpstreamTimeoutError();
    }
    throw error;
  } finally {
    clearTimeout(timeoutId);
  }
}

export function buildUpstreamHeaders(request: Request, url: URL): Headers {
  const headers = new Headers();

  for (const headerName of FORWARDED_UPSTREAM_HEADER_NAMES) {
    const value = request.headers.get(headerName);
    if (value) {
      headers.set(headerName, value);
    }
  }

  headers.set("x-forwarded-host", url.host);
  headers.set("x-forwarded-proto", url.protocol.replace(":", ""));
  return headers;
}

export async function readRequestBodyWithinLimit(
  request: Request,
  maxBytes: number,
): Promise<RequestBodyReadResult> {
  const contentLength = request.headers.get("content-length");
  if (contentLength !== null) {
    const size = Number.parseInt(contentLength, 10);
    if (!Number.isFinite(size) || size < 0) {
      return {
        ok: false,
        status: 400,
        error: "Invalid Content-Length header",
      };
    }
    if (size > maxBytes) {
      return {
        ok: false,
        status: 413,
        error: "Request body too large",
      };
    }
  }

  if (!request.body) {
    return { ok: true, body: new Uint8Array() };
  }

  const reader = request.body.getReader();
  const chunks: Uint8Array[] = [];
  let totalBytes = 0;

  try {
    while (true) {
      const { done, value } = await reader.read();
      if (done) {
        break;
      }

      const chunk = value ?? new Uint8Array();
      totalBytes += chunk.byteLength;
      if (totalBytes > maxBytes) {
        await reader.cancel();
        return {
          ok: false,
          status: 413,
          error: "Request body too large",
        };
      }

      chunks.push(chunk);
    }
  } finally {
    reader.releaseLock();
  }

  const body = new Uint8Array(totalBytes);
  let offset = 0;
  for (const chunk of chunks) {
    body.set(chunk, offset);
    offset += chunk.byteLength;
  }

  return { ok: true, body };
}

function json(payload: unknown, status: number): Response {
  const headers = new Headers({
    "content-type": "application/json; charset=utf-8",
  });
  applyCors(headers);
  return new Response(JSON.stringify(payload, null, 2), {
    status,
    headers,
  });
}

function html(payload: string, status: number, options: { cacheable?: boolean } = {}): Response {
  const headers = new Headers({
    "content-type": "text/html; charset=utf-8",
    "x-proxied-by": "osv-mirror-worker",
  });
  if (options.cacheable) {
    applyPublicCacheHeaders(headers);
  }
  applyCors(headers);
  return new Response(payload, {
    status,
    headers,
  });
}

function withCors(response: Response): Response {
  const headers = new Headers(response.headers);
  applyCors(headers);
  return new Response(response.body, {
    status: response.status,
    statusText: response.statusText,
    headers,
  });
}

function applyCors(headers: Headers): void {
  // Open CORS is intentional so browser-based tools can call the public mirror directly.
  headers.set("access-control-allow-origin", "*");
  headers.set("access-control-allow-methods", "GET,POST,OPTIONS");
  headers.set("access-control-allow-headers", "content-type");
  headers.set("access-control-max-age", "86400");
}

function applyPublicCacheHeaders(headers: Headers): void {
  headers.set(
    "cache-control",
    `public, max-age=${BROWSER_CACHE_MAX_AGE_SECONDS}, s-maxage=${EDGE_CACHE_MAX_AGE_SECONDS}`,
  );
}

async function serveVulnerabilityPage(
  requestUrl: URL,
  env: Env,
  vulnerabilityId: string,
  ctx: ExecutionContext,
): Promise<Response> {
  const cacheKey = new Request(`${requestUrl.origin}${requestUrl.pathname}`, { method: "GET" });
  const cachedResponse = await caches.default.match(cacheKey);
  if (cachedResponse) {
    return cachedResponse;
  }

  const normalizedOrigin = normalizeOrigin(env.OSV_ORIGIN);
  const upstreamUrl = `${normalizedOrigin}/v1/vulns/${encodeURIComponent(vulnerabilityId)}`;

  try {
    const upstreamResponse = await fetchUpstreamWithTimeout(upstreamUrl, {
      method: "GET",
      headers: new Headers({ accept: "application/json" }),
      redirect: "follow",
    });

    if (!upstreamResponse.ok) {
      return html(
        renderErrorPage(
          vulnerabilityId,
          `Unable to load mirrored OSV details from ${normalizedOrigin}. Upstream responded with ${upstreamResponse.status} ${upstreamResponse.statusText}.`,
        ),
        upstreamResponse.status,
      );
    }

    const vulnerability = (await upstreamResponse.json()) as OsvVulnerability;
    const response = html(renderVulnerabilityDetailPage(requestUrl, vulnerability), 200, {
      cacheable: true,
    });
    ctx.waitUntil(caches.default.put(cacheKey, response.clone()));
    return response;
  } catch (error) {
    return html(
      renderErrorPage(
        vulnerabilityId,
        error instanceof UpstreamTimeoutError
          ? error.message
          : error instanceof Error
            ? error.message
            : "Unknown error while querying the upstream OSV API.",
      ),
      error instanceof UpstreamTimeoutError ? 504 : 502,
    );
  }
}

export function renderVulnerabilityDetailPage(requestUrl: URL, vulnerability: OsvVulnerability): string {
  const vulnerabilityId = vulnerability.id?.trim() || "Unknown vulnerability";
  const title = vulnerability.summary?.trim() || vulnerabilityId;
  const summary = vulnerability.summary?.trim() || "No summary provided.";
  const detailSource = vulnerability.details?.trim() || summary;
  const mirrorJsonUrl = `${requestUrl.origin}/v1/vulns/${encodeURIComponent(vulnerabilityId)}`;
  const officialOsvUrl = `https://osv.dev/vulnerability/${encodeURIComponent(vulnerabilityId)}`;

  return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>${escapeHtml(vulnerabilityId)} · OSV Mirror</title>
  <style>
    :root {
      --bg: #f5efe4;
      --panel: #fffaf2;
      --ink: #182126;
      --muted: #627077;
      --accent: #0b6e4f;
      --border: #d9c9b2;
      --shadow: 0 24px 48px rgba(24, 33, 38, 0.09);
      --chip: #f2eadc;
      --chip-ink: #5f4c2c;
    }
    * { box-sizing: border-box; }
    body {
      margin: 0;
      font-family: "Segoe UI", "Helvetica Neue", sans-serif;
      color: var(--ink);
      background: radial-gradient(circle at top left, #fff8eb, var(--bg) 58%, #ece3d2);
      line-height: 1.55;
    }
    main {
      width: min(1080px, calc(100vw - 32px));
      margin: 28px auto 64px;
    }
    .hero, .panel {
      background: var(--panel);
      border: 1px solid var(--border);
      border-radius: 24px;
      box-shadow: var(--shadow);
      padding: 24px;
      margin-bottom: 20px;
    }
    h1, h2 { margin-top: 0; }
    h1 { margin-bottom: 8px; }
    .lede, .meta-label, .empty, .severity-score, .affected-meta, .range-events { color: var(--muted); }
    .meta-grid {
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(180px, 1fr));
      gap: 14px;
      margin-top: 20px;
    }
    .meta-card, .severity-item, .reference-item, .affected-item, .range-card {
      border: 1px solid var(--border);
      border-radius: 16px;
      padding: 14px 16px;
      background: #fffef9;
    }
    .meta-value, .severity-type, .reference-type, .affected-name, .range-head {
      font-weight: 700;
    }
    .actions {
      display: flex;
      gap: 12px;
      flex-wrap: wrap;
      margin-top: 18px;
    }
    .action {
      display: inline-flex;
      align-items: center;
      padding: 10px 16px;
      border-radius: 999px;
      border: 1px solid transparent;
      background: var(--accent);
      color: #fff;
      text-decoration: none;
      font-weight: 600;
    }
    .action.secondary {
      background: transparent;
      border-color: var(--border);
      color: var(--ink);
    }
    .columns {
      display: grid;
      grid-template-columns: minmax(0, 1.35fr) minmax(280px, 0.85fr);
      gap: 20px;
    }
    .badge-row {
      display: flex;
      flex-wrap: wrap;
      gap: 8px;
      margin-bottom: 12px;
    }
    .badge {
      display: inline-flex;
      align-items: center;
      padding: 6px 10px;
      border-radius: 999px;
      background: var(--chip);
      color: var(--chip-ink);
      font-size: 0.92rem;
    }
    .severity-list, .reference-list, .affected-list {
      list-style: none;
      padding: 0;
      margin: 0;
      display: grid;
      gap: 12px;
    }
    .details p {
      margin: 0 0 14px;
    }
    .details p:last-child {
      margin-bottom: 0;
    }
    .stack {
      display: grid;
      gap: 12px;
    }
    .reference-url, .range-link {
      color: var(--accent);
      text-decoration: none;
      overflow-wrap: anywhere;
      word-break: break-word;
    }
    @media (max-width: 860px) {
      main {
        width: calc(100vw - 20px);
        margin: 16px auto 32px;
      }
      .hero, .panel {
        padding: 18px;
        border-radius: 18px;
      }
      .columns {
        grid-template-columns: 1fr;
      }
    }
  </style>
</head>
<body>
  <main>
    <section class="hero">
      <div class="badge-row">
        <span class="badge">OSV Mirror</span>
        <span class="badge">${escapeHtml(vulnerabilityId)}</span>
      </div>
      <h1>${escapeHtml(title)}</h1>
      <p class="lede">${escapeHtml(summary)}</p>
      <div class="actions">
        <a class="action" href="${escapeHtml(mirrorJsonUrl)}" target="_blank" rel="noreferrer">Open mirrored JSON</a>
        <a class="action secondary" href="${escapeHtml(officialOsvUrl)}" target="_blank" rel="noreferrer">Official OSV page</a>
      </div>
      <div class="meta-grid">
        <div class="meta-card">
          <div class="meta-label">Published</div>
          <div class="meta-value">${escapeHtml(formatTimestamp(vulnerability.published))}</div>
        </div>
        <div class="meta-card">
          <div class="meta-label">Modified</div>
          <div class="meta-value">${escapeHtml(formatTimestamp(vulnerability.modified))}</div>
        </div>
        <div class="meta-card">
          <div class="meta-label">Withdrawn</div>
          <div class="meta-value">${escapeHtml(formatTimestamp(vulnerability.withdrawn))}</div>
        </div>
        <div class="meta-card">
          <div class="meta-label">Aliases</div>
          <div class="meta-value">${escapeHtml(renderAliasSummary(vulnerability.aliases))}</div>
        </div>
      </div>
    </section>

    <div class="columns">
      <section class="panel">
        <h2>Details</h2>
        <div class="details">
          ${renderTextBlocks(detailSource)}
        </div>
      </section>

      <section class="panel">
        <h2>Severity</h2>
        ${renderSeverityList(vulnerability.severity)}
      </section>
    </div>

    <div class="columns">
      <section class="panel">
        <h2>Affected Packages</h2>
        ${renderAffectedPackages(vulnerability.affected)}
      </section>

      <section class="panel">
        <h2>References</h2>
        ${renderReferenceList(vulnerability.references)}
      </section>
    </div>
  </main>
</body>
</html>`;
}

function renderErrorPage(vulnerabilityId: string, message: string): string {
  return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>${escapeHtml(vulnerabilityId)} · OSV Mirror Error</title>
  <style>
    body {
      margin: 0;
      font-family: "Segoe UI", "Helvetica Neue", sans-serif;
      background: #f7f1e7;
      color: #182126;
    }
    main {
      width: min(720px, calc(100vw - 32px));
      margin: 48px auto;
      padding: 24px;
      background: #fffaf2;
      border: 1px solid #d9c9b2;
      border-radius: 20px;
    }
    p { color: #5f4c2c; }
  </style>
</head>
<body>
  <main>
    <h1>${escapeHtml(vulnerabilityId)}</h1>
    <p>${escapeHtml(message)}</p>
  </main>
</body>
</html>`;
}

function renderAliasSummary(aliases: string[] | undefined): string {
  const values = (aliases ?? []).map((alias) => alias.trim()).filter(Boolean);
  return values.length > 0 ? values.join(", ") : "n/a";
}

function renderTextBlocks(text: string): string {
  const normalized = text.trim();
  if (!normalized) {
    return '<p class="empty">No additional details provided.</p>';
  }

  return normalized
    .split(/\r?\n\s*\r?\n/g)
    .map((paragraph) => paragraph.trim())
    .filter(Boolean)
    .map((paragraph) => `<p>${escapeHtml(paragraph).replace(/\r?\n/g, "<br>")}</p>`)
    .join("");
}

function renderSeverityList(severity: OsvSeverity[] | undefined): string {
  const entries = (severity ?? [])
    .map((entry) => ({
      type: entry.type?.trim() || "Score",
      score: entry.score?.trim() || "unknown",
    }))
    .filter((entry) => entry.score.length > 0);

  if (entries.length === 0) {
    return '<p class="empty">No severity metadata provided.</p>';
  }

  return `<ul class="severity-list">${entries
    .map(
      (entry) => `<li class="severity-item"><div class="severity-type">${escapeHtml(entry.type)}</div><div class="severity-score">${escapeHtml(entry.score)}</div></li>`,
    )
    .join("")}</ul>`;
}

function renderReferenceList(references: OsvReference[] | undefined): string {
  const seenUrls = new Set<string>();
  const entries = (references ?? [])
    .map((reference) => {
      const safeUrl = toSafeExternalUrl(reference.url);
      if (!safeUrl) {
        return null;
      }

      return {
        type: reference.type?.trim() || "Reference",
        url: safeUrl,
      };
    })
    .filter((reference): reference is { type: string; url: string } => reference !== null)
    .filter((reference) => {
      const key = reference.url.toLowerCase();
      if (seenUrls.has(key)) {
        return false;
      }
      seenUrls.add(key);
      return true;
    });

  if (entries.length === 0) {
    return '<p class="empty">No external references were provided.</p>';
  }

  return `<ul class="reference-list">${entries
    .map(
      (reference) => `<li class="reference-item"><div class="reference-type">${escapeHtml(humanizeIdentifier(reference.type))}</div><a class="reference-url" href="${escapeHtml(reference.url)}" target="_blank" rel="noreferrer">${escapeHtml(reference.url)}</a></li>`,
    )
    .join("")}</ul>`;
}

function renderAffectedPackages(affected: OsvAffectedPackage[] | undefined): string {
  const entries = (affected ?? []).filter(
    (entry) => entry.package || (entry.versions?.length ?? 0) > 0 || (entry.ranges?.length ?? 0) > 0,
  );
  if (entries.length === 0) {
    return '<p class="empty">No affected package metadata provided.</p>';
  }

  return `<ul class="affected-list">${entries.map((entry) => renderAffectedPackage(entry)).join("")}</ul>`;
}

function renderAffectedPackage(entry: OsvAffectedPackage): string {
  const packageLabel =
    [entry.package?.ecosystem?.trim(), entry.package?.name?.trim()].filter(Boolean).join(" / ") ||
    entry.package?.purl?.trim() ||
    "Unknown package";
  const versions = entry.versions?.filter((version) => version.trim().length > 0) ?? [];
  const versionLine = versions.length > 0 ? `<div class="affected-meta">Versions: ${escapeHtml(versions.join(", "))}</div>` : "";
  const ranges = renderAffectedRanges(entry.ranges);

  return `<li class="affected-item"><div class="affected-name">${escapeHtml(packageLabel)}</div>${versionLine}${ranges}</li>`;
}

function renderAffectedRanges(ranges: OsvAffectedRange[] | undefined): string {
  const entries = (ranges ?? []).filter(
    (range) => (range.events?.length ?? 0) > 0 || toSafeExternalUrl(range.repo) !== null,
  );
  if (entries.length === 0) {
    return "";
  }

  return `<div class="stack">${entries.map((range) => renderAffectedRange(range)).join("")}</div>`;
}

function renderAffectedRange(range: OsvAffectedRange): string {
  const events = (range.events ?? [])
    .map((event) =>
      Object.entries(event)
        .filter(([, value]) => typeof value === "string" && value.trim().length > 0)
        .map(([key, value]) => `${humanizeIdentifier(key)}: ${value}`)
        .join(" • "),
    )
    .filter(Boolean);
  const safeRepoUrl = toSafeExternalUrl(range.repo);
  const repoLink = safeRepoUrl
    ? `<a class="range-link" href="${escapeHtml(safeRepoUrl)}" target="_blank" rel="noreferrer">${escapeHtml(safeRepoUrl)}</a>`
    : "";
  const eventLine = events.length > 0 ? `<div class="range-events">${escapeHtml(events.join(" | "))}</div>` : "";

  return `<div class="range-card"><div class="range-head">${escapeHtml(range.type?.trim() || "Unknown range")}</div>${repoLink}${eventLine}</div>`;
}

export function toSafeExternalUrl(value: string | undefined): string | null {
  const trimmed = value?.trim();
  if (!trimmed) {
    return null;
  }

  try {
    const parsed = new URL(trimmed);
    if (parsed.protocol !== "http:" && parsed.protocol !== "https:") {
      return null;
    }
    return parsed.toString();
  } catch {
    return null;
  }
}

export function humanizeIdentifier(value: string): string {
  return value
    .split(/[_\-\s]+/)
    .filter(Boolean)
    .map((segment) => {
      const lettersOnly = segment.replace(/[^A-Za-z]/g, "");
      if (
        lettersOnly.length >= 2 &&
        lettersOnly.length <= 5 &&
        lettersOnly === lettersOnly.toUpperCase() &&
        segment !== segment.toLowerCase()
      ) {
        return segment;
      }

      return segment.charAt(0).toUpperCase() + segment.slice(1).toLowerCase();
    })
    .join(" ");
}

function formatTimestamp(value: string | undefined): string {
  if (!value || value.trim().length === 0) {
    return "n/a";
  }

  const parsed = new Date(value);
  if (Number.isNaN(parsed.valueOf())) {
    return value;
  }
  return parsed.toISOString();
}

function escapeHtml(value: string): string {
  return value
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/\"/g, "&quot;")
    .replace(/'/g, "&#39;");
}