
import crypto from "node:crypto";

function getCookie(req, name) {
  const cookies = (req.headers.cookie || "").split(";");
  const item = cookies.find(
    (c) => c.trim().startsWith(name + "=")
  );
  return item ? item.trim().slice(name.length + 1) : "";
}

function decryptToken(value, secret) {
  const [ivPart, tagPart, encryptedPart] = value.split(".");

  if (!ivPart || !tagPart || !encryptedPart) {
    throw new Error("Invalid encrypted token");
  }

  const key = crypto.scryptSync(
    secret,
    "security-defender-gmail-token-v1",
    32
  );

  const decipher = crypto.createDecipheriv(
    "aes-256-gcm",
    key,
    Buffer.from(ivPart, "base64url")
  );

  decipher.setAuthTag(Buffer.from(tagPart, "base64url"));

  return Buffer.concat([
    decipher.update(
      Buffer.from(encryptedPart, "base64url")
    ),
    decipher.final()
  ]).toString("utf8");
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

export default async function handler(req, res) {
  res.setHeader("Cache-Control", "no-store");

  if (req.method !== "GET") {
    return res.status(405).json({
      error: "Method not allowed"
    });
  }

  const {
    NEXT_PUBLIC_SUPABASE_URL,
    SUPABASE_SECRET_KEY,
    SESSION_SECRET,
    GOOGLE_CLIENT_ID,
    GOOGLE_CLIENT_SECRET
  } = process.env;

  if (
    !NEXT_PUBLIC_SUPABASE_URL ||
    !SUPABASE_SECRET_KEY ||
    !SESSION_SECRET ||
    !GOOGLE_CLIENT_ID ||
    !GOOGLE_CLIENT_SECRET
  ) {
    return res.status(500).json({
      error: "Server configuration is incomplete"
    });
  }

  const sessionToken = getCookie(req, "sd_session");

  if (!sessionToken || sessionToken.length < 32) {
    return res.status(401).json({
      error: "Please sign in first"
    });
  }

  const supabaseUrl = NEXT_PUBLIC_SUPABASE_URL.replace(/\/$/, "");

  const headers = {
    apikey: SUPABASE_SECRET_KEY,
    Authorization: `Bearer ${SUPABASE_SECRET_KEY}`,
    "Content-Type": "application/json"
  };

  try {
    const sessionHash = crypto
      .createHash("sha256")
      .update(sessionToken)
      .digest("hex");

    const sessionResponse = await fetch(
      `${supabaseUrl}/rest/v1/app_sessions?session_hash=eq.${sessionHash}&select=google_sub,email,expires_at`,
      { headers }
    );

    if (!sessionResponse.ok) {
      return res.status(500).json({
        error: "Could not verify login"
      });
    }

    const sessions = await sessionResponse.json();
    const session = sessions[0];

    if (
      !session ||
      new Date(session.expires_at).getTime() <= Date.now()
    ) {
      return res.status(401).json({
        error: "Your session has expired. Please sign in again."
      });
    }

    const connectionResponse = await fetch(
      `${supabaseUrl}/rest/v1/gmail_connections?google_sub=eq.${encodeURIComponent(session.google_sub)}&select=email,access_token_encrypted,refresh_token_encrypted,token_expires_at`,
      { headers }
    );

    if (!connectionResponse.ok) {
      return res.status(500).json({
        error: "Could not retrieve Gmail connection"
      });
    }

    const connections = await connectionResponse.json();
    const connection = connections[0];

    if (!connection) {
      return res.status(404).json({
        error: "No Gmail connection found. Please connect Google again."
      });
    }

    let accessToken = decryptToken(
      connection.access_token_encrypted,
      SESSION_SECRET
    );

    const expiry = new Date(
      connection.token_expires_at
    ).getTime();

    if (!expiry || expiry <= Date.now() + 60000) {
      if (!connection.refresh_token_encrypted) {
        return res.status(401).json({
          error: "Please reconnect Google to restore Gmail access."
        });
      }

      const refreshToken = decryptToken(
        connection.refresh_token_encrypted,
        SESSION_SECRET
      );

      const refreshResponse = await fetch(
        "https://oauth2.googleapis.com/token",
        {
          method: "POST",
          headers: {
            "Content-Type": "application/x-www-form-urlencoded"
          },
          body: new URLSearchParams({
            client_id: GOOGLE_CLIENT_ID,
            client_secret: GOOGLE_CLIENT_SECRET,
            refresh_token: refreshToken,
            grant_type: "refresh_token"
          })
        }
      );

      const refreshed = await refreshResponse.json();

      if (!refreshResponse.ok || !refreshed.access_token) {
        return res.status(401).json({
          error: "Gmail access expired. Please reconnect Google."
        });
      }

      accessToken = refreshed.access_token;

      const updateResponse = await fetch(
        `${supabaseUrl}/rest/v1/gmail_connections?google_sub=eq.${encodeURIComponent(session.google_sub)}`,
        {
          method: "PATCH",
          headers: {
            ...headers,
            Prefer: "return=minimal"
          },
          body: JSON.stringify({
            access_token_encrypted: encryptToken(
              accessToken,
              SESSION_SECRET
            ),
            token_expires_at: new Date(
              Date.now() + Number(refreshed.expires_in || 3600) * 1000
            ).toISOString(),
            updated_at: new Date().toISOString()
          })
        }
      );

      if (!updateResponse.ok) {
        return res.status(500).json({
          error: "Could not update Gmail connection"
        });
      }
    }

    const gmailResponse = await fetch(
      "https://gmail.googleapis.com/gmail/v1/users/me/messages?maxResults=10&labelIds=INBOX",
      {
        headers: {
          Authorization: `Bearer ${accessToken}`
        }
      }
    );

    const gmailData = await gmailResponse.json();

    if (!gmailResponse.ok) {
      return res.status(502).json({
        error: "Gmail could not provide inbox messages"
      });
    }

    const messageIds = (gmailData.messages || []).slice(0, 10);

    const messages = await Promise.all(
      messageIds.map(async (item) => {
        const response = await fetch(
          `https://gmail.googleapis.com/gmail/v1/users/me/messages/${encodeURIComponent(item.id)}?format=metadata&metadataHeaders=From&metadataHeaders=Subject&metadataHeaders=Date`,
          {
            headers: {
              Authorization: `Bearer ${accessToken}`
            }
          }
        );

        if (!response.ok) {
          return null;
        }

        const message = await response.json();
        const fields = message.payload?.headers || [];

        const getHeader = (name) =>
          fields.find(
            (header) => header.name.toLowerCase() === name.toLowerCase()
          )?.value || "";

        return {
          id: message.id,
          threadId: message.threadId,
          snippet: message.snippet || "",
          from: getHeader("From"),
          subject: getHeader("Subject"),
          date: getHeader("Date"),
          unread: (message.labelIds || []).includes("UNREAD")
        };
      })
    );

    return res.status(200).json({
      connected: true,
      email: connection.email,
      totalReturned: messages.filter(Boolean).length,
      messages: messages.filter(Boolean)
    });
  } catch (error) {
    return res.status(500).json({
      error: "Could not load Gmail inbox"
    });
  }
}
