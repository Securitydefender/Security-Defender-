
import crypto from "node:crypto";

function getCookie(req, name) {
  const cookies = (req.headers.cookie || "").split(";");
  const item = cookies.find(
    (c) => c.trim().startsWith(name + "=")
  );
  return item ? item.trim().slice(name.length + 1) : "";
}

function encryptToken(token, secret) {
  const key = crypto.scryptSync(
    secret,
    "security-defender-gmail-token-v1",
    32
  );
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv("aes-256-gcm", key, iv);
  const encrypted = Buffer.concat([
    cipher.update(token, "utf8"),
    cipher.final()
  ]);

  return [
    iv.toString("base64url"),
    cipher.getAuthTag().toString("base64url"),
    encrypted.toString("base64url")
  ].join(".");
}

function clearOAuthCookies() {
  return [
    "oauth_state=; HttpOnly; Secure; SameSite=Lax; Path=/; Max-Age=0",
    "oauth_signature=; HttpOnly; Secure; SameSite=Lax; Path=/; Max-Age=0"
  ];
}

export default async function handler(req, res) {
  res.setHeader("Cache-Control", "no-store");

  if (req.method !== "GET") {
    return res.status(405).send("Method not allowed");
  }

  const {
    GOOGLE_CLIENT_ID,
    GOOGLE_CLIENT_SECRET,
    GOOGLE_REDIRECT_URI,
    SESSION_SECRET,
    NEXT_PUBLIC_SUPABASE_URL,
    SUPABASE_SECRET_KEY
  } = process.env;

  if (
    !GOOGLE_CLIENT_ID ||
    !GOOGLE_CLIENT_SECRET ||
    !GOOGLE_REDIRECT_URI ||
    !SESSION_SECRET ||
    !NEXT_PUBLIC_SUPABASE_URL ||
    !SUPABASE_SECRET_KEY
  ) {
    return res.status(500).send("Server configuration is incomplete.");
  }

  const url = new URL(
    req.url,
    "https://security-defender-app.vercel.app"
  );

  const code = url.searchParams.get("code");
  const returnedState = url.searchParams.get("state");
  const savedState = getCookie(req, "oauth_state");
  const savedSignature = getCookie(req, "oauth_signature");

  if (url.searchParams.get("error")) {
    res.setHeader("Set-Cookie", clearOAuthCookies());
    return res.status(400).send("Google authorization was cancelled.");
  }

  if (!code || !returnedState || !savedState || !savedSignature) {
    res.setHeader("Set-Cookie", clearOAuthCookies());
    return res.status(400).send("Authorization response is incomplete.");
  }

  const expectedSignature = crypto
    .createHmac("sha256", SESSION_SECRET)
    .update(savedState)
    .digest("hex");

  const actual = Buffer.from(savedSignature, "hex");
  const expected = Buffer.from(expectedSignature, "hex");

  if (
    returnedState !== savedState ||
    actual.length !== expected.length ||
    !crypto.timingSafeEqual(actual, expected)
  ) {
    res.setHeader("Set-Cookie", clearOAuthCookies());
    return res.status(403).send("Authorization state validation failed.");
  }

  try {
    const tokenResponse = await fetch(
      "https://oauth2.googleapis.com/token",
      {
        method: "POST",
        headers: {
          "Content-Type": "application/x-www-form-urlencoded"
        },
        body: new URLSearchParams({
          code,
          client_id: GOOGLE_CLIENT_ID,
          client_secret: GOOGLE_CLIENT_SECRET,
          redirect_uri: GOOGLE_REDIRECT_URI,
          grant_type: "authorization_code"
        })
      }
    );

    const tokens = await tokenResponse.json();

    if (!tokenResponse.ok || !tokens.access_token) {
      res.setHeader("Set-Cookie", clearOAuthCookies());
      return res.status(400).send("Google token exchange failed.");
    }

    const profileResponse = await fetch(
      "https://www.googleapis.com/oauth2/v3/userinfo",
      {
        headers: {
          Authorization: `Bearer ${tokens.access_token}`
        }
      }
    );

    const profile = await profileResponse.json();

    if (
      !profileResponse.ok ||
      !profile.sub ||
      !profile.email ||
      profile.email_verified !== true
    ) {
      res.setHeader("Set-Cookie", clearOAuthCookies());
      return res.status(400).send("Google account verification failed.");
    }

    const supabaseUrl = NEXT_PUBLIC_SUPABASE_URL.replace(/\/$/, "");
    const apiHeaders = {
      apikey: SUPABASE_SECRET_KEY,
      Authorization: `Bearer ${SUPABASE_SECRET_KEY}`,
      "Content-Type": "application/json"
    };

    const connection = {
      google_sub: profile.sub,
      email: profile.email,
      access_token_encrypted: encryptToken(
        tokens.access_token,
        SESSION_SECRET
      ),
      token_expires_at: new Date(
        Date.now() + Number(tokens.expires_in || 3600) * 1000
      ).toISOString(),
      scopes: tokens.scope || "",
      updated_at: new Date().toISOString()
    };

    if (tokens.refresh_token) {
      connection.refresh_token_encrypted = encryptToken(
        tokens.refresh_token,
        SESSION_SECRET
      );
    }

    const connectionResponse = await fetch(
      `${supabaseUrl}/rest/v1/gmail_connections?on_conflict=google_sub`,
      {
        method: "POST",
        headers: {
          ...apiHeaders,
          Prefer: "resolution=merge-duplicates,return=minimal"
        },
        body: JSON.stringify(connection)
      }
    );

    if (!connectionResponse.ok) {
      res.setHeader("Set-Cookie", clearOAuthCookies());
      return res.status(500).send("Could not save the Gmail connection.");
    }

    const sessionToken = crypto.randomBytes(32).toString("base64url");
    const sessionHash = crypto
      .createHash("sha256")
      .update(sessionToken)
      .digest("hex");

    const expiresAt = new Date(
      Date.now() + 7 * 24 * 60 * 60 * 1000
    ).toISOString();

    const sessionResponse = await fetch(
      `${supabaseUrl}/rest/v1/app_sessions`,
      {
        method: "POST",
        headers: {
          ...apiHeaders,
          Prefer: "return=minimal"
        },
        body: JSON.stringify({
          session_hash: sessionHash,
          google_sub: profile.sub,
          email: profile.email,
          expires_at: expiresAt
        })
      }
    );

    if (!sessionResponse.ok) {
      res.setHeader("Set-Cookie", clearOAuthCookies());
      return res.status(500).send("Could not create the login session.");
    }

    res.setHeader("Set-Cookie", [
      ...clearOAuthCookies(),
      `sd_session=${sessionToken}; HttpOnly; Secure; SameSite=Lax; Path=/; Max-Age=604800`
    ]);

    return res.status(200).send(
      "Google account connected and login session created."
    );
  } catch (error) {
    res.setHeader("Set-Cookie", clearOAuthCookies());
    return res.status(500).send("Authorization could not be completed.");
  }
}
