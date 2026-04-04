/**
 * Gmail OAuth 2.0 helpers.
 * Uses google.com authorization code flow with gmail.metadata scope.
 * (gmail.metadata is NOT a restricted scope — approved immediately,
 *  gives access to headers: From, To, Subject, Date — no body content)
 */

const CLIENT_ID     = process.env.GOOGLE_CLIENT_ID!;
const CLIENT_SECRET = process.env.GOOGLE_CLIENT_SECRET!;
const REDIRECT_URI  = process.env.GMAIL_REDIRECT_URI || "https://scamshieldy.com/api/gmail/callback";

const SCOPES = [
  "openid",
  "email",
  // Use metadata (non-restricted) scope — read headers without body
  "https://www.googleapis.com/auth/gmail.metadata",
].join(" ");

export interface GoogleTokens {
  access_token: string;
  refresh_token?: string;
  expires_in: number;
  token_type: string;
  id_token?: string;
}

export interface GoogleUserInfo {
  email: string;
  sub: string;
}

/** Build the Google OAuth authorization URL */
export function buildAuthUrl(state: string): string {
  const params = new URLSearchParams({
    client_id: CLIENT_ID,
    redirect_uri: REDIRECT_URI,
    response_type: "code",
    scope: SCOPES,
    access_type: "offline",
    prompt: "consent",  // force consent screen to always get refresh_token
    state,
  });
  return "https://accounts.google.com/o/oauth2/v2/auth?" + params.toString();
}

/** Exchange authorization code for tokens */
export async function exchangeCode(code: string): Promise<GoogleTokens> {
  const res = await fetch("https://oauth2.googleapis.com/token", {
    method: "POST",
    headers: { "Content-Type": "application/x-www-form-urlencoded" },
    body: new URLSearchParams({
      code,
      client_id: CLIENT_ID,
      client_secret: CLIENT_SECRET,
      redirect_uri: REDIRECT_URI,
      grant_type: "authorization_code",
    }),
  });
  if (!res.ok) {
    const err = await res.text();
    throw new Error("Token exchange failed: " + err);
  }
  return res.json();
}

/** Use a refresh token to get a new access token */
export async function refreshAccessToken(refreshToken: string): Promise<{ access_token: string; expires_in: number }> {
  const res = await fetch("https://oauth2.googleapis.com/token", {
    method: "POST",
    headers: { "Content-Type": "application/x-www-form-urlencoded" },
    body: new URLSearchParams({
      refresh_token: refreshToken,
      client_id: CLIENT_ID,
      client_secret: CLIENT_SECRET,
      grant_type: "refresh_token",
    }),
  });
  if (!res.ok) {
    const err = await res.text();
    throw new Error("Token refresh failed: " + err);
  }
  return res.json();
}

/** Decode the id_token JWT to extract user email (no signature verify needed here — server-side only) */
export function extractEmailFromIdToken(idToken: string): string | null {
  try {
    const payload = idToken.split(".")[1];
    const decoded = JSON.parse(Buffer.from(payload, "base64url").toString());
    return decoded.email ?? null;
  } catch {
    return null;
  }
}

/** Revoke a token (call on disconnect) */
export async function revokeToken(token: string): Promise<void> {
  await fetch("https://oauth2.googleapis.com/revoke?token=" + encodeURIComponent(token), {
    method: "POST",
    headers: { "Content-Type": "application/x-www-form-urlencoded" },
  });
}
