export interface Env {
  OSV_ORIGIN?: string;
}

const DEFAULT_OSV_ORIGIN = "https://api.osv.dev";

export default {
  async fetch(request: Request, env: Env): Promise<Response> {
    const url = new URL(request.url);

    if (request.method === "OPTIONS") {
      return withCors(new Response(null, { status: 204 }));
    }

    if (request.method === "GET" && (url.pathname === "/" || url.pathname === "/healthz")) {
      return json(
        {
          name: "osv-mirror-worker",
          status: "ok",
          upstream: normalizeOrigin(env.OSV_ORIGIN),
          supportedPaths: ["POST /v1/querybatch", "GET /v1/vulns/{id}"],
        },
        200,
      );
    }

    if (!isSupportedPath(url.pathname, request.method)) {
      return json(
        {
          error: "Unsupported path",
          supportedPaths: ["POST /v1/querybatch", "GET /v1/vulns/{id}"],
        },
        404,
      );
    }

    const upstreamUrl = `${normalizeOrigin(env.OSV_ORIGIN)}${url.pathname}${url.search}`;
    const headers = new Headers(request.headers);
    headers.set("x-forwarded-host", url.host);
    headers.set("x-forwarded-proto", url.protocol.replace(":", ""));

    try {
      const upstreamResponse = await fetch(upstreamUrl, {
        method: request.method,
        headers,
        body: request.method === "GET" || request.method === "HEAD" ? undefined : request.body,
        redirect: "follow",
      });

      const responseHeaders = new Headers(upstreamResponse.headers);
      responseHeaders.set("x-proxied-by", "osv-mirror-worker");
      applyCors(responseHeaders);

      return new Response(upstreamResponse.body, {
        status: upstreamResponse.status,
        statusText: upstreamResponse.statusText,
        headers: responseHeaders,
      });
    } catch (error) {
      return json(
        {
          error: "Upstream OSV request failed",
          details: error instanceof Error ? error.message : "Unknown error",
        },
        502,
      );
    }
  },
} satisfies ExportedHandler<Env>;

function isSupportedPath(pathname: string, method: string): boolean {
  if (pathname === "/v1/querybatch") {
    return method === "POST";
  }

  if (pathname.startsWith("/v1/vulns/")) {
    const suffix = pathname.slice("/v1/vulns/".length);
    return method === "GET" && suffix.length > 0 && !suffix.includes("/");
  }

  return false;
}

function normalizeOrigin(origin: string | undefined): string {
  const value = origin?.trim().replace(/\/+$/, "");
  if (!value) {
    return DEFAULT_OSV_ORIGIN;
  }
  return value;
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
  headers.set("access-control-allow-origin", "*");
  headers.set("access-control-allow-methods", "GET,POST,OPTIONS");
  headers.set("access-control-allow-headers", "content-type,authorization");
}