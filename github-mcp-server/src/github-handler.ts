import type { AuthRequest, OAuthHelpers } from "@cloudflare/workers-oauth-provider";
import { Hono } from "hono";
import { Octokit } from "octokit";
import { fetchUpstreamAuthToken, getUpstreamAuthorizeUrl, Props } from "./utils";
import { clientIdAlreadyApproved, parseRedirectApproval, renderApprovalDialog } from "./workers-oauth-utils";

const app = new Hono<{ Bindings: Env & { OAUTH_PROVIDER: OAuthHelpers } }>();

// Función helper para logging seguro (sin exponer secrets)
function safeLog(message: string, data?: any) {
  const sanitized = data ? JSON.parse(JSON.stringify(data)) : {};
  // Ocultar información sensible
  if (sanitized.clientSecret) sanitized.clientSecret = '[REDACTED]';
  if (sanitized.accessToken) sanitized.accessToken = '[REDACTED]';
  if (sanitized.GITHUB_CLIENT_SECRET) sanitized.GITHUB_CLIENT_SECRET = '[REDACTED]';
  
  console.log(`[GitHub OAuth] ${message}`, sanitized);
}

// Detectar y obtener credenciales de GitHub
function getGitHubCredentials(request: Request, env: Env): {
  clientId: string;
  clientSecret: string;
  isCustom: boolean;
} {
  safeLog("Getting GitHub credentials");
  
  const url = new URL(request.url);
  
  // Opción 1: Custom app via query params
  const customClientId = url.searchParams.get('custom_client_id');
  const customClientSecret = url.searchParams.get('custom_client_secret');
  
  if (customClientId && customClientSecret) {
    safeLog("Using custom GitHub app from query params");
    return {
      clientId: customClientId,
      clientSecret: customClientSecret,
      isCustom: true
    };
  }
  
  // Opción 2: Custom app via headers
  const authHeader = request.headers.get('X-GitHub-OAuth-Credentials');
  if (authHeader) {
    try {
      const decoded = atob(authHeader);
      const [clientId, clientSecret] = decoded.split(':');
      if (clientId && clientSecret) {
        safeLog("Using custom GitHub app from headers");
        return {
          clientId,
          clientSecret,
          isCustom: true
        };
      }
    } catch (e) {
      safeLog("Failed to decode auth header", { error: e });
    }
  }
  
  // Por defecto: usar app compartida
  safeLog("Using shared GitHub app", { 
    clientId: env.GITHUB_CLIENT_ID,
    hasSecret: !!env.GITHUB_CLIENT_SECRET 
  });
  
  return {
    clientId: env.GITHUB_CLIENT_ID,
    clientSecret: env.GITHUB_CLIENT_SECRET,
    isCustom: false
  };
}

// Guardar info de custom app en el state
function encodeStateWithCustomApp(
  oauthReqInfo: AuthRequest,
  customApp?: { clientId: string; clientSecret: string; isCustom: boolean }
): string {
  const stateData = {
    ...oauthReqInfo,
    ...(customApp?.isCustom ? { customApp } : {})
  };
  const encoded = btoa(JSON.stringify(stateData));
  safeLog("Encoded state", { 
    hasCustomApp: !!customApp?.isCustom,
    stateLength: encoded.length 
  });
  return encoded;
}

// OAuth Discovery endpoint - requerido por MCP
app.get("/.well-known/oauth-protected-resource", (c) => {
  safeLog("GET /.well-known/oauth-protected-resource");
  
  const origin = new URL(c.req.url).origin;
  
  return c.json({
    resource: origin,
    oauth_authorization_server: `${origin}/.well-known/oauth-authorization-server`
  }, {
    headers: {
      "Access-Control-Allow-Origin": "*",
      "Access-Control-Allow-Methods": "GET, OPTIONS",
      "Access-Control-Allow-Headers": "Content-Type"
    }
  });
});

// CORS preflight handler para discovery
app.options("/.well-known/oauth-protected-resource", (c) => {
  safeLog("OPTIONS /.well-known/oauth-protected-resource");
  
  return new Response(null, {
    status: 204,
    headers: {
      "Access-Control-Allow-Origin": "*",
      "Access-Control-Allow-Methods": "GET, OPTIONS",
      "Access-Control-Allow-Headers": "Content-Type",
      "Access-Control-Max-Age": "86400"
    }
  });
});

app.get("/authorize", async (c) => {
  safeLog("GET /authorize");
  
  try {
    const oauthReqInfo = await c.env.OAUTH_PROVIDER.parseAuthRequest(c.req.raw);
    safeLog("Parsed auth request", { 
      clientId: oauthReqInfo.clientId,
      scope: oauthReqInfo.scope,
      redirectUri: oauthReqInfo.redirectUri 
    });
    
    const { clientId } = oauthReqInfo;
    if (!clientId) {
      safeLog("ERROR: No client ID");
      return c.text("Invalid request - missing client ID", 400);
    }

    if (await clientIdAlreadyApproved(c.req.raw, oauthReqInfo.clientId, c.env.COOKIE_ENCRYPTION_KEY)) {
      safeLog("Client already approved, redirecting to GitHub");
      return redirectToGithub(c.req.raw, oauthReqInfo, {}, c.env);
    }

    safeLog("Showing approval dialog");
    const client = await c.env.OAUTH_PROVIDER.lookupClient(clientId);
    return renderApprovalDialog(c.req.raw, {
      client,
      server: {
        name: "Cloudflare GitHub MCP Server",
        logo: "https://avatars.githubusercontent.com/u/314135?s=200&v=4",
        description: "This is a demo MCP Remote Server using GitHub for authentication.",
      },
      state: { oauthReqInfo },
    });
  } catch (e) {
    safeLog("ERROR in /authorize", { error: e });
    return c.text(`Error: ${e instanceof Error ? e.message : 'Unknown error'}`, 500);
  }
});

app.post("/authorize", async (c) => {
  safeLog("POST /authorize");
  
  try {
    const { state, headers } = await parseRedirectApproval(c.req.raw, c.env.COOKIE_ENCRYPTION_KEY);
    safeLog("Parsed approval", { hasState: !!state, hasHeaders: !!headers });
    
    if (!state.oauthReqInfo) {
      safeLog("ERROR: No oauthReqInfo in state");
      return c.text("Invalid request - missing OAuth info", 400);
    }

    return redirectToGithub(c.req.raw, state.oauthReqInfo, headers, c.env);
  } catch (e) {
    safeLog("ERROR in POST /authorize", { error: e });
    return c.text(`Error: ${e instanceof Error ? e.message : 'Unknown error'}`, 500);
  }
});

async function redirectToGithub(
  request: Request, 
  oauthReqInfo: AuthRequest, 
  headers: Record<string, string> = {},
  env: Env
) {
  safeLog("Redirecting to GitHub");
  
  const redirectUri = new URL("/callback", request.url).href;
  safeLog("Callback URI", { redirectUri });
  
  // Obtener credenciales (compartidas o custom)
  const githubCreds = getGitHubCredentials(request, env);
  
  // Verificar que tenemos las credenciales necesarias
  if (!githubCreds.clientId || !githubCreds.clientSecret) {
    safeLog("ERROR: Missing GitHub credentials", {
      hasClientId: !!githubCreds.clientId,
      hasClientSecret: !!githubCreds.clientSecret
    });
    throw new Error("GitHub credentials not configured");
  }
  
  // Codificar info de custom app en el state si aplica
  const state = encodeStateWithCustomApp(oauthReqInfo, githubCreds);
  
  const githubUrl = getUpstreamAuthorizeUrl({
    upstream_url: "https://github.com/login/oauth/authorize",
    scope: "repo user:email notifications admin:org workflow",
    client_id: githubCreds.clientId,
    redirect_uri: redirectUri,
    state: state,
  });
  
  safeLog("GitHub authorize URL", { 
    url: githubUrl.substring(0, 50) + "...",
    hasState: !!state 
  });
  
  return new Response(null, {
    status: 302,
    headers: {
      ...headers,
      location: githubUrl,
    },
  });
}

app.get("/callback", async (c) => {
  safeLog("GET /callback");
  
  const error = c.req.query("error");
  if (error) {
    const errorDesc = c.req.query("error_description") || "Unknown error";
    safeLog("OAuth error from GitHub", { error, errorDesc });
    return c.text(`OAuth error: ${error} - ${errorDesc}`, 400);
  }

  const code = c.req.query("code");
  const stateParam = c.req.query("state");
  
  safeLog("Callback params", { 
    hasCode: !!code, 
    hasState: !!stateParam,
    codeLength: code?.length,
    stateLength: stateParam?.length
  });

  if (!code || !stateParam) {
    safeLog("ERROR: Missing code or state");
    return c.text("Missing required parameters", 400);
  }

  // Decodificar state con posible info de custom app
  let oauthReqInfo: AuthRequest & { customApp?: any };
  try {
    oauthReqInfo = JSON.parse(atob(stateParam));
    safeLog("Decoded state", { 
      hasClientId: !!oauthReqInfo.clientId,
      hasCustomApp: !!oauthReqInfo.customApp,
      clientId: oauthReqInfo.clientId
    });
  } catch (e) {
    safeLog("ERROR: Failed to decode state", { error: e });
    return c.text("Invalid state parameter", 400);
  }
  
  if (!oauthReqInfo.clientId) {
    safeLog("ERROR: No clientId in state");
    return c.text("Invalid state - missing client ID", 400);
  }

  // Determinar qué credenciales usar
  const githubClientId = oauthReqInfo.customApp?.clientId || c.env.GITHUB_CLIENT_ID;
  const githubClientSecret = oauthReqInfo.customApp?.clientSecret || c.env.GITHUB_CLIENT_SECRET;
  const isCustomApp = !!oauthReqInfo.customApp?.isCustom;
  
  safeLog("Using credentials", { 
    isCustomApp,
    clientId: githubClientId,
    hasSecret: !!githubClientSecret
  });
  
  // Exchange code for token
  const redirectUri = new URL("/callback", c.req.url).href;
  const [accessToken, errResponse] = await fetchUpstreamAuthToken({
    upstream_url: "https://github.com/login/oauth/access_token",
    client_id: githubClientId,
    client_secret: githubClientSecret,
    code: code,
    redirect_uri: redirectUri,
  });
  
  if (errResponse) {
    safeLog("ERROR: Failed to exchange token", { 
      status: errResponse.status,
      statusText: errResponse.statusText 
    });
    const errorText = await errResponse.text();
    console.error("Token exchange error details:", errorText);
    return new Response(`Failed to exchange token: ${errorText}`, { status: 500 });
  }

  safeLog("Token exchanged successfully");

  // Fetch user info y rate limits
  try {
    const octokit = new Octokit({ auth: accessToken });
    
    // Obtener info del usuario
    safeLog("Fetching user info");
    const user = await octokit.rest.users.getAuthenticated();
    const { login, name, email } = user.data;
    safeLog("User info retrieved", { login, name, hasEmail: !!email });
    
    // Obtener rate limits
    let rateLimit = null;
    try {
      const rateLimitResponse = await octokit.rest.rateLimit.get();
      rateLimit = {
        remaining: rateLimitResponse.data.rate.remaining,
        limit: rateLimitResponse.data.rate.limit,
        reset: rateLimitResponse.data.rate.reset
      };
      safeLog("Rate limit info", rateLimit);
    } catch (e) {
      safeLog("WARNING: Failed to get rate limit", { error: e });
    }
    
    // Complete authorization con info adicional
    safeLog("Completing authorization");
    const { redirectTo } = await c.env.OAUTH_PROVIDER.completeAuthorization({
      request: oauthReqInfo,
      userId: login,
      metadata: {
        label: name || login,
        description: isCustomApp 
          ? `Using custom GitHub App (${rateLimit?.remaining || '?'}/${rateLimit?.limit || '?'} API calls remaining)`
          : `Using shared GitHub App (${rateLimit?.remaining || '?'}/${rateLimit?.limit || '?'} API calls remaining)`
      },
      scope: oauthReqInfo.scope,
      props: {
        login,
        name: name || login,
        email: email || "",
        accessToken,
        tokenCreatedAt: Date.now(),
        isCustomApp,
        rateLimit
      } as Props,
    });

    safeLog("Authorization completed, redirecting", { 
      redirectTo: redirectTo.substring(0, 50) + "..." 
    });
    return Response.redirect(redirectTo);
  } catch (e) {
    safeLog("ERROR in callback final stage", { error: e });
    return c.text(`Error processing callback: ${e instanceof Error ? e.message : 'Unknown error'}`, 500);
  }
});

// Endpoint para setup e instrucciones
app.get("/setup", async (c) => {
  safeLog("GET /setup");
  const baseUrl = new URL(c.req.url).origin;
  
  return c.html(`
    <!DOCTYPE html>
    <html>
    <head>
      <title>GitHub MCP Setup</title>
      <style>
        body { font-family: system-ui; max-width: 800px; margin: 40px auto; padding: 20px; }
        .option { margin: 20px 0; padding: 20px; background: #f5f5f5; border-radius: 8px; }
        code { background: #e0e0e0; padding: 2px 6px; border-radius: 3px; }
        .button { background: #0366d6; color: white; padding: 10px 20px; text-decoration: none; border-radius: 6px; display: inline-block; }
        .error { background: #fee; color: #c00; padding: 10px; border-radius: 4px; margin: 10px 0; }
      </style>
    </head>
    <body>
      <h1>GitHub MCP Server</h1>
      
      <div class="option">
        <h2>Option 1: Quick Start (Recommended)</h2>
        <p>Use our shared GitHub App. No configuration needed.</p>
        <p>Connection URL: <code>${baseUrl}</code></p>
      </div>
      
      <div class="option">
        <h2>Option 2: Use Your Own GitHub App</h2>
        <p>For dedicated rate limits, create your own GitHub OAuth App:</p>
        <ol>
          <li>Go to <a href="https://github.com/settings/developers" target="_blank">GitHub Settings → Developer settings → OAuth Apps</a></li>
          <li>Click "New OAuth App"</li>
          <li>Fill in:
            <ul>
              <li>Application name: <code>My MCP Server</code></li>
              <li>Homepage URL: <code>${baseUrl}</code></li>
              <li>Authorization callback URL: <code>${baseUrl}/callback</code></li>
            </ul>
          </li>
          <li>Create the app and generate a client secret</li>
          <li>Use this connection URL:<br>
          <code>${baseUrl}?custom_client_id=YOUR_CLIENT_ID&custom_client_secret=YOUR_CLIENT_SECRET</code></li>
        </ol>
      </div>
      
      <div class="option">
        <h3>Rate Limits</h3>
        <p><strong>Shared App:</strong> 5,000 requests/hour shared among all users</p>
        <p><strong>Your Own App:</strong> 5,000 requests/hour just for you</p>
      </div>
    </body>
    </html>
  `);
});

// Health check endpoint
app.get("/health", (c) => {
  safeLog("GET /health");
  return c.json({ 
    status: "ok", 
    timestamp: new Date().toISOString(),
    hasGitHubCreds: !!(c.env.GITHUB_CLIENT_ID && c.env.GITHUB_CLIENT_SECRET),
    hasCookieKey: !!c.env.COOKIE_ENCRYPTION_KEY
  });
});

// Catch-all OPTIONS handler para CORS
app.options("*", (c) => {
  return new Response(null, {
    status: 204,
    headers: {
      "Access-Control-Allow-Origin": "*",
      "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
      "Access-Control-Allow-Headers": "Content-Type, Authorization",
      "Access-Control-Max-Age": "86400"
    }
  });
});

// Export único
export const GitHubHandler = app;