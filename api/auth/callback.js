
import crypto from "node:crypto";

function getCookie(req, name) {
  const cookies = (req.headers.cookie || "").split(";");
  const item = cookies.find((c) => c.trim().startsWith(name + "="));
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
  const tag = cipher.getAuthTag();

  return [
    iv.toString("base64url"),
    tag.toString("base64url"),
    encrypted.toString("base64url")
  ].join(".");
}

function clearCookies() {
  return [
    "oauth_state=; HttpOnly; Secure; SameSite=Lax; Path=/; Max-Age=0",
    "oauth_signature=; HttpOnly; Secure; SameSite=Lax; Path=/; Max-Age=0"
  ];
}

export default async function handler(req, res) {
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

  const url = new URL(req.url, "https://security-defender-app.vercel.app");
  const code = url.searchParams.get("code");
  const returnedState = url.searchParams.get("state");
  const savedState = getCookie(req, "oauth_state");
  const savedSignature = getCookie(req, "oauth_signature");

  res.setHeader("Set-Cookie", clearCookies());

  if (url.searchParams.get("error")) {
    return res.status(400).send("Google authorization was not completed.");
  }

  if (!code || !returnedState || !savedState || !savedSignature) {
    return res.status(400).send("Authorization response is incomplete.");
  }

  const expectedSignature = crypto
    .createHmac("sha256", SESSION_SECRET)
    .update(savedState)
    .digest("hex");

  const signatureBuffer = Buffer.from(savedSignature, "hex");
  const expectedBuffer = Buffer.from(expectedSignature, "hex");

  if (
    returnedState !== savedState ||
    signatureBuffer.length !== expectedBuffer.length ||
    !crypto.timingSafeEqual(signatureBuffer, expectedBuffer)
  ) {
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

    if (!profileResponse.ok || !profile.sub || !profile.email) {
      return res.status(400).send("Could not verify the Google account.");
    }

    const record = {
      google_sub: profile.sub,
      email: profile.email,
      access_token_encrypted: encryptToken(
        tokens.access_token,
        SESSION_SECRET
      ),
      refresh_token_encrypted: tokens.refresh_token
        ? encryptToken(tokens.refresh_token, SESSION_SECRET)
        : null,
      token_expires_at: new Date(
        Date.now() + Number(tokens.expires_in || 3600) * 1000
      ).toISOString(),
      scopes: tokens.scope || "",
      updated_at: new Date().toISOString()
    };

    const databaseResponse = await fetch(
      `${NEXT_PUBLIC_SUPABASE_URL}/rest/v1/gmail_connections?on_conflict=google_sub`,
      {
        method: "POST",
        headers: {
          apikey: SUPABASE_SECRET_KEY,
          Authorization: `Bearer ${SUPABASE_SECRET_KEY}`,
          "Content-Type": "application/json",
          Prefer: "resolution=merge-duplicates,return=minimal"
        },
        body: JSON.stringify(record)
      }
    );

    if (!databaseResponse.ok) {
      return res.status(500).send("Could not securely save the Gmail connection.");
    }

    return res.status(200).send(
      "Google authorization completed. Your Gmail connection was saved."
    );
  } catch (error) {
    return res.status(500).send("Authorization could not be completed.");
  }
}
