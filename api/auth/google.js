
import crypto from "node:crypto";

export default function handler(req, res) {
  if (req.method !== "GET") {
    return res.status(405).send("Method not allowed");
  }

  const clientId = process.env.GOOGLE_CLIENT_ID;
  const redirectUri = process.env.GOOGLE_REDIRECT_URI;
  const sessionSecret = process.env.SESSION_SECRET;

  if (!clientId || !redirectUri || !sessionSecret) {
    return res.status(500).send(
      "OAuth configuration is incomplete."
    );
  }

  const state = crypto.randomBytes(32).toString("hex");

  const signature = crypto
    .createHmac("sha256", sessionSecret)
    .update(state)
    .digest("hex");

  res.setHeader("Set-Cookie", [
    `oauth_state=${state}; HttpOnly; Secure; SameSite=Lax; Path=/; Max-Age=600`,
    `oauth_signature=${signature}; HttpOnly; Secure; SameSite=Lax; Path=/; Max-Age=600`
  ]);

  const params = new URLSearchParams({
    client_id: clientId,
    redirect_uri: redirectUri,
    response_type: "code",
    scope: "openid email profile https://www.googleapis.com/auth/gmail.modify",
    access_type: "offline",
    prompt: "consent",
    state
  });

  return res.redirect(
    302,
    "https://accounts.google.com/o/oauth2/v2/auth?" +
    params.toString()
  );
}

