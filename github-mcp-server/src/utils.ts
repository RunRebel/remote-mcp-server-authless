// Tipos para las respuestas de GitHub OAuth
interface GitHubTokenResponse {
  access_token?: string;
  token_type?: string;
  scope?: string;
  error?: string;
  error_description?: string;
  error_uri?: string;
}

/**
 * Constructs an authorization URL for an upstream service.
 *
 * @param {Object} options
 * @param {string} options.upstream_url - The base URL of the upstream service.
 * @param {string} options.client_id - The client ID of the application.
 * @param {string} options.redirect_uri - The redirect URI of the application.
 * @param {string} [options.state] - The state parameter.
 *
 * @returns {string} The authorization URL.
 */
export function getUpstreamAuthorizeUrl({
  upstream_url,
  client_id,
  scope,
  redirect_uri,
  state,
}: {
  upstream_url: string;
  client_id: string;
  scope: string;
  redirect_uri: string;
  state?: string;
}) {
  const upstream = new URL(upstream_url);
  upstream.searchParams.set("client_id", client_id);
  upstream.searchParams.set("redirect_uri", redirect_uri);
  upstream.searchParams.set("scope", scope);
  if (state) upstream.searchParams.set("state", state);
  upstream.searchParams.set("response_type", "code");
  return upstream.href;
}

/**
 * Fetches an authorization token from an upstream service.
 *
 * @param {Object} options
 * @param {string} options.client_id - The client ID of the application.
 * @param {string} options.client_secret - The client secret of the application.
 * @param {string} options.code - The authorization code.
 * @param {string} options.redirect_uri - The redirect URI of the application.
 * @param {string} options.upstream_url - The token endpoint URL of the upstream service.
 *
 * @returns {Promise<[string, null] | [null, Response]>} A promise that resolves to an array containing the access token or an error response.
 */
export async function fetchUpstreamAuthToken({
  client_id,
  client_secret,
  code,
  redirect_uri,
  upstream_url,
}: {
  code: string | undefined;
  upstream_url: string;
  client_id: string;
  client_secret: string;
  redirect_uri: string;
}): Promise<[string, null] | [null, Response]> {
  if (!code) {
    return [null, new Response("Missing code", { status: 400 })];
  }

  try {
    const resp = await fetch(upstream_url, {
      method: "POST",
      headers: {
        "Content-Type": "application/x-www-form-urlencoded",
        "Accept": "application/json", // Importante para GitHub
      },
      body: new URLSearchParams({ 
        client_id, 
        client_secret, 
        code, 
        redirect_uri 
      }).toString(),
    });
    
    if (!resp.ok) {
      const errorText = await resp.text();
      console.error(`GitHub token exchange failed (${resp.status}):`, errorText);
      return [null, new Response(`Failed to exchange token: ${resp.status}`, { status: 500 })];
    }
    
    // GitHub puede devolver JSON o form-encoded
    const contentType = resp.headers.get('content-type');
    let accessToken: string | null = null;
    
    if (contentType?.includes('application/json')) {
      const data = await resp.json() as GitHubTokenResponse;
      if (data.error) {
        console.error("GitHub OAuth error:", data);
        return [null, new Response(`GitHub error: ${data.error_description || data.error}`, { status: 400 })];
      }
      accessToken = data.access_token || null;
    } else {
      // Form-encoded response
      const body = await resp.formData();
      accessToken = body.get("access_token") as string;
    }
    
    if (!accessToken) {
      return [null, new Response("Missing access token in response", { status: 400 })];
    }
    
    return [accessToken, null];
  } catch (error) {
    console.error("Error in fetchUpstreamAuthToken:", error);
    return [null, new Response("Failed to exchange token", { status: 500 })];
  }
}

// Context from the auth process, encrypted & stored in the auth token
// and provided to the DurableMCP as this.props
export type Props = {
  login: string;
  name: string;
  email: string;
  accessToken: string;
  tokenCreatedAt?: number;      // Timestamp de creación del token
  isCustomApp?: boolean;         // Si usa app custom de GitHub
  rateLimit?: {                  // Info de rate limits
    remaining: number;
    limit: number;
    reset: number;
  };
};