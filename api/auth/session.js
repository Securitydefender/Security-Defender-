
import crypto from "node:crypto";

function getCookie(req, name) {
  const cookies = (req.headers.cookie || "").split(";");
  const item = cookies.find(
    (c) => c.trim().startsWith(name + "=")
  );
  return item ? item.trim().slice(name.length + 1) : "";
}

export default async function handler(req, res) {
  res.setHeader("Cache-Control", "no-store");

  if (req.method !== "GET") {
    return res.status(405).json({ error: "Method not allowed" });
  }

  const supabaseUrl = process.env.NEXT_PUBLIC_SUPABASE_URL;
  const secretKey = process.env.SUPABASE_SECRET_KEY;

  if (!supabaseUrl || !secretKey) {
    return res.status(500).json({
      error: "Server configuration is incomplete"
    });
  }

  const token = getCookie(req, "sd_session");

  if (!token || token.length < 32) {
    return res.status(401).json({
      authenticated: false
    });
  }

  try {
    const sessionHash = crypto
      .createHash("sha256")
      .update(token)
      .digest("hex");

    const response = await fetch(
      `${supabaseUrl.replace(/\/$/, "")}/rest/v1/app_sessions?session_hash=eq.${sessionHash}&select=google_sub,email,expires_at`,
      {
        headers: {
          apikey: secretKey,
          Authorization: `Bearer ${secretKey}`
        }
      }
    );

    if (!response.ok) {
      return res.status(500).json({
        error: "Could not verify session"
      });
    }

    const sessions = await response.json();
    const session = sessions[0];

    if (
      !session ||
      new Date(session.expires_at).getTime() <= Date.now()
    ) {
      res.setHeader("Set-Cookie",
        "sd_session=; HttpOnly; Secure; SameSite=Lax; Path=/; Max-Age=0"
      );

      return res.status(401).json({
        authenticated: false
      });
    }

    return res.status(200).json({
      authenticated: true,
      email: session.email
    });
  } catch (error) {
    return res.status(500).json({
      error: "Session verification failed"
    });
  }
}
