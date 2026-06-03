import { afterEach, describe, expect, it, vi } from "vitest";

import worker, {
  buildUpstreamHeaders,
  getVulnerabilityPageId,
  humanizeIdentifier,
  isSupportedApiPath,
  MAX_QUERYBATCH_BYTES,
  MAX_QUERYBATCH_QUERIES,
  UPSTREAM_FETCH_TIMEOUT_MS,
  renderVulnerabilityDetailPage,
  toSafeExternalUrl,
} from "./index";

function createExecutionContext() {
  const pending: Promise<unknown>[] = [];

  return {
    ctx: {
      waitUntil(promise: Promise<unknown>) {
        pending.push(promise);
      },
      passThroughOnException() {},
    } as ExecutionContext,
    async drain() {
      await Promise.all(pending);
    },
  };
}

function createCacheStubs() {
  const match = vi.fn().mockResolvedValue(undefined);
  const put = vi.fn().mockResolvedValue(undefined);
  (globalThis as typeof globalThis & { caches?: CacheStorage }).caches = {
    default: {
      match,
      put,
    },
  } as unknown as CacheStorage;

  return { match, put };
}

const originalCaches = (globalThis as typeof globalThis & { caches?: CacheStorage }).caches;

afterEach(() => {
  vi.restoreAllMocks();
  vi.useRealTimers();
  (globalThis as typeof globalThis & { caches?: CacheStorage }).caches = originalCaches;
});

describe("upstream proxy hardening", () => {
  it("forwards only explicitly allowed request headers", () => {
    const request = new Request("https://mirror.example.workers.dev/v1/querybatch", {
      method: "POST",
      headers: {
        accept: "application/json",
        "content-type": "application/json",
        authorization: "Bearer secret-token",
        cookie: "session=abc123",
      },
      body: "{}",
    });

    const headers = buildUpstreamHeaders(request, new URL(request.url));

    expect(headers.get("accept")).toBe("application/json");
    expect(headers.get("content-type")).toBe("application/json");
    expect(headers.get("authorization")).toBeNull();
    expect(headers.get("cookie")).toBeNull();
    expect(headers.get("x-forwarded-host")).toBe("mirror.example.workers.dev");
    expect(headers.get("x-forwarded-proto")).toBe("https");
  });

  it("rejects oversized POST bodies before contacting the upstream", async () => {
    createCacheStubs();
    const fetchSpy = vi.spyOn(globalThis, "fetch");
    const { ctx } = createExecutionContext();
    const request = new Request("https://mirror.example.workers.dev/v1/querybatch", {
      method: "POST",
      headers: {
        "content-type": "application/json",
      },
      body: "x".repeat(MAX_QUERYBATCH_BYTES + 1),
    });

    const response = await worker.fetch(request, { OSV_ORIGIN: "https://api.osv.dev" }, ctx);

    expect(response.status).toBe(413);
    expect(fetchSpy).not.toHaveBeenCalled();
    await expect(response.json()).resolves.toMatchObject({
      error: "Request body too large",
      maxBytes: MAX_QUERYBATCH_BYTES,
    });
  });

  it("rejects query parameters on supported API and advisory routes", async () => {
    createCacheStubs();
    const fetchSpy = vi.spyOn(globalThis, "fetch");

    const apiResponse = await worker.fetch(
      new Request("https://mirror.example.workers.dev/v1/vulns/OSV-2026-1?foo=bar"),
      { OSV_ORIGIN: "https://api.osv.dev" },
      createExecutionContext().ctx,
    );
    const advisoryResponse = await worker.fetch(
      new Request("https://mirror.example.workers.dev/vulnerability/OSV-2026-1?foo=bar"),
      { OSV_ORIGIN: "https://api.osv.dev" },
      createExecutionContext().ctx,
    );

    expect(apiResponse.status).toBe(400);
    await expect(apiResponse.json()).resolves.toEqual({
      error: "Query parameters are not supported on this route",
    });
    expect(advisoryResponse.status).toBe(400);
    await expect(advisoryResponse.json()).resolves.toEqual({
      error: "Query parameters are not supported on this route",
    });
    expect(fetchSpy).not.toHaveBeenCalled();
  });

  it("requires application/json for querybatch requests", async () => {
    createCacheStubs();
    const fetchSpy = vi.spyOn(globalThis, "fetch");

    const response = await worker.fetch(
      new Request("https://mirror.example.workers.dev/v1/querybatch", {
        method: "POST",
        headers: {
          "content-type": "text/plain",
        },
        body: "{}",
      }),
      { OSV_ORIGIN: "https://api.osv.dev" },
      createExecutionContext().ctx,
    );

    expect(response.status).toBe(415);
    await expect(response.json()).resolves.toEqual({
      error: "Content-Type must be application/json",
    });
    expect(fetchSpy).not.toHaveBeenCalled();
  });

  it("rejects malformed and structurally invalid querybatch payloads", async () => {
    createCacheStubs();
    const fetchSpy = vi.spyOn(globalThis, "fetch");

    const malformedResponse = await worker.fetch(
      new Request("https://mirror.example.workers.dev/v1/querybatch", {
        method: "POST",
        headers: {
          "content-type": "application/json; charset=utf-8",
        },
        body: "{",
      }),
      { OSV_ORIGIN: "https://api.osv.dev" },
      createExecutionContext().ctx,
    );
    const invalidShapeResponse = await worker.fetch(
      new Request("https://mirror.example.workers.dev/v1/querybatch", {
        method: "POST",
        headers: {
          "content-type": "application/json",
        },
        body: JSON.stringify({ queries: ["not-an-object"] }),
      }),
      { OSV_ORIGIN: "https://api.osv.dev" },
      createExecutionContext().ctx,
    );

    expect(malformedResponse.status).toBe(400);
    await expect(malformedResponse.json()).resolves.toEqual({
      error: "Request body must be valid JSON",
    });
    expect(invalidShapeResponse.status).toBe(400);
    await expect(invalidShapeResponse.json()).resolves.toEqual({
      error: "Each query must be a JSON object",
    });
    expect(fetchSpy).not.toHaveBeenCalled();
  });

  it("rejects querybatch payloads that exceed the semantic batch limit", async () => {
    createCacheStubs();
    const fetchSpy = vi.spyOn(globalThis, "fetch");

    const response = await worker.fetch(
      new Request("https://mirror.example.workers.dev/v1/querybatch", {
        method: "POST",
        headers: {
          "content-type": "application/json",
        },
        body: JSON.stringify({
          queries: Array.from({ length: MAX_QUERYBATCH_QUERIES + 1 }, () => ({
            package: {
              ecosystem: "npm",
              name: "left-pad",
            },
            version: "1.3.0",
          })),
        }),
      }),
      { OSV_ORIGIN: "https://api.osv.dev" },
      createExecutionContext().ctx,
    );

    expect(response.status).toBe(413);
    await expect(response.json()).resolves.toEqual({
      error: "Too many queries in batch",
      maxQueries: MAX_QUERYBATCH_QUERIES,
    });
    expect(fetchSpy).not.toHaveBeenCalled();
  });

  it("caches successful GET vulnerability lookups", async () => {
    const cache = createCacheStubs();
    const fetchSpy = vi.spyOn(globalThis, "fetch").mockResolvedValue(
      new Response(JSON.stringify({ id: "OSV-2026-1" }), {
        status: 200,
        headers: {
          "content-type": "application/json",
        },
      }),
    );
    const execution = createExecutionContext();
    const request = new Request("https://mirror.example.workers.dev/v1/vulns/OSV-2026-1");

    const response = await worker.fetch(request, { OSV_ORIGIN: "https://api.osv.dev" }, execution.ctx);
    await execution.drain();

    expect(fetchSpy).toHaveBeenCalledOnce();
    expect(cache.put).toHaveBeenCalledOnce();
    expect(response.headers.get("cache-control")).toContain("s-maxage=300");
    expect(response.headers.get("access-control-max-age")).toBe("86400");
  });
});

describe("rendering hardening", () => {
  it("renders only safe external links", () => {
    const html = renderVulnerabilityDetailPage(
      new URL("https://mirror.example.workers.dev/vulnerability/OSV-2026-1"),
      {
        id: "OSV-2026-1",
        summary: "Example advisory",
        details: "Detailed advisory text",
        references: [
          { type: "WEB", url: "javascript:alert(1)" },
          { type: "ADVISORY", url: "https://example.com/advisories/OSV-2026-1" },
        ],
        affected: [
          {
            ranges: [
              {
                type: "GIT",
                repo: "javascript:alert(2)",
                events: [{ introduced: "0" }],
              },
            ],
          },
        ],
      },
    );

    expect(html).toContain("https://example.com/advisories/OSV-2026-1");
    expect(html).not.toContain('href="javascript:alert(1)"');
    expect(html).not.toContain('href="javascript:alert(2)"');
  });

  it("preserves short uppercase acronyms when humanizing identifiers", () => {
    expect(humanizeIdentifier("CVSS_V3")).toBe("CVSS V3");
    expect(humanizeIdentifier("GHSA")).toBe("GHSA");
    expect(humanizeIdentifier("last_affected")).toBe("Last Affected");
  });

  it("validates supported API and vulnerability page paths", () => {
    expect(isSupportedApiPath("/v1/querybatch", "POST")).toBe(true);
    expect(isSupportedApiPath("/v1/querybatch", "GET")).toBe(false);
    expect(isSupportedApiPath("/v1/vulns/OSV-2026-1", "GET")).toBe(true);
    expect(isSupportedApiPath("/v1/vulns/OSV-2026-1/extra", "GET")).toBe(false);
    expect(isSupportedApiPath("/v1/vulns/OSV-2026-1%2Fextra", "GET")).toBe(false);
    expect(getVulnerabilityPageId("/vulnerability/OSV-2026-1")).toBe("OSV-2026-1");
    expect(getVulnerabilityPageId("/vulnerability/OSV-2026-1%2Fextra")).toBeNull();
    expect(toSafeExternalUrl("https://example.com/reference")).toBe("https://example.com/reference");
    expect(toSafeExternalUrl("javascript:alert(1)")).toBeNull();
  });

  it("returns a bounded error when the upstream OSV request times out", async () => {
    createCacheStubs();
    vi.useFakeTimers();

    vi.spyOn(globalThis, "fetch").mockImplementation(
      async (_input: RequestInfo | URL, init?: RequestInit): Promise<Response> =>
        new Promise((_resolve, reject) => {
          init?.signal?.addEventListener("abort", () => {
            reject(new DOMException("The operation was aborted.", "AbortError"));
          });
        }),
    );

    const responsePromise = worker.fetch(
      new Request("https://mirror.example.workers.dev/v1/vulns/OSV-2026-1"),
      { OSV_ORIGIN: "https://api.osv.dev" },
      createExecutionContext().ctx,
    );

    await vi.advanceTimersByTimeAsync(UPSTREAM_FETCH_TIMEOUT_MS + 1);

    const response = await responsePromise;

    expect(response.status).toBe(504);
    await expect(response.json()).resolves.toEqual({
      error: "Upstream OSV request timed out",
      details: "Upstream OSV request timed out",
    });
  });
});