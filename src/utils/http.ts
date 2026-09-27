import axios, { AxiosResponse } from "axios";
import * as https from "https";
import * as tls from "tls";
import { URL } from "url";

export interface HttpResponseData {
  url: string;
  statusCode: number;
  statusText: string;
  headers: Record<string, string>;
  rawHeaders: Record<string, string | string[] | undefined>;
  body: string;
  responseTimeMs: number;
  tlsInfo?: {
    authorized: boolean;
    protocol?: string;
    cipher?: string;
    certExpiry?: string;
  };
}

export async function fetchEndpointData(
  targetUrl: string,
  timeoutMs: number = 8000
): Promise<HttpResponseData> {
  const startTime = Date.now();
  const parsed = new URL(targetUrl);
  const isHttps = parsed.protocol === "https:";

  let tlsInfo: HttpResponseData["tlsInfo"] | undefined;

  const agent = isHttps
    ? new https.Agent({
        rejectUnauthorized: false, // allow inspection even if self-signed to report accurately
      })
    : undefined;

  const response: AxiosResponse = await axios.get(targetUrl, {
    timeout: timeoutMs,
    maxRedirects: 5,
    validateStatus: () => true, // Don't throw on 4xx/5xx so we can audit error pages
    httpsAgent: agent,
    headers: {
      "User-Agent":
        "VibeAudit/1.0 (OWASP & Web Vibe Security Scanner; +https://github.com/nguyenquocanhz/VibeAudit)",
      Accept:
        "text/html,application/xhtml+xml,application/xml;q=0.9,application/json,*/*;q=0.8",
    },
  });

  const duration = Date.now() - startTime;

  // Flatten headers to lowercase keys for consistent lookup
  const headers: Record<string, string> = {};
  for (const [key, val] of Object.entries(response.headers)) {
    headers[key.toLowerCase()] = Array.isArray(val) ? val.join(", ") : String(val);
  }

  // Attempt TLS inspection if https
  if (isHttps) {
    try {
      const socket = response.request?.res?.socket;
      if (socket && typeof socket.getPeerCertificate === "function") {
        const cert = socket.getPeerCertificate();
        tlsInfo = {
          authorized: Boolean(socket.authorized),
          protocol: socket.getProtocol?.(),
          cipher: socket.getCipher?.()?.name,
          certExpiry: cert?.valid_to,
        };
      }
    } catch {
      // TLS info probe is best-effort
    }
  }

  return {
    url: targetUrl,
    statusCode: response.status,
    statusText: response.statusText,
    headers,
    rawHeaders: response.headers,
    body: typeof response.data === "string" ? response.data : JSON.stringify(response.data),
    responseTimeMs: duration,
    tlsInfo,
  };
}

export async function probePath(
  baseUrl: string,
  subpath: string,
  timeoutMs: number = 4000
): Promise<{ status: number; exists: boolean; snippet?: string }> {
  try {
    const target = new URL(subpath, baseUrl).toString();
    const resp = await axios.get(target, {
      timeout: timeoutMs,
      maxRedirects: 2,
      validateStatus: () => true,
      headers: {
        "User-Agent": "VibeAudit/1.0 PathProbe",
      },
    });

    const isExposed =
      resp.status >= 200 &&
      resp.status < 300 &&
      typeof resp.data === "string" &&
      resp.data.length > 0;

    let snippet: string | undefined;
    if (isExposed && typeof resp.data === "string") {
      snippet = resp.data.slice(0, 120).replace(/[\r\n]+/g, " ");
    }

    return { status: resp.status, exists: isExposed, snippet };
  } catch {
    return { status: 0, exists: false };
  }
}
