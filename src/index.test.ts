import { afterEach, describe, expect, it, vi } from "vitest";

import worker, {
  buildUpstreamHeaders,
  getVulnerabilityPageId,
  humanizeIdentifier,
  isSupportedApiPath,
  MAX_QUERYBATCH_BYTES,
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
    expect(getVulnerabilityPageId("/vulnerability/OSV-2026-1")).toBe("OSV-2026-1");
    expect(getVulnerabilityPageId("/vulnerability/OSV-2026-1%2Fextra")).toBeNull();
    expect(toSafeExternalUrl("https://example.com/reference")).toBe("https://example.com/reference");
    expect(toSafeExternalUrl("javascript:alert(1)")).toBeNull();
  });
});