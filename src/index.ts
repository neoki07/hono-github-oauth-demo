import { Hono } from "hono";
import { githubAuth } from "@hono/oauth-providers/github";
import { getCookie, setCookie } from "hono/cookie";

type Bindings = {
  SESSION_STORE_KV: KVNamespace;
};

const app = new Hono<{ Bindings: Bindings }>();

app.use("/auth/github/login", githubAuth({}));

app
  .get("/auth/github/login", async (c) => {
    const oldSessionId = getCookie(c, "session_id");
    if (oldSessionId) {
      setCookie(c, "session_id", "", {
        httpOnly: true,
        secure: true,
        sameSite: "None",
        maxAge: 0,
      });

      await c.env.SESSION_STORE_KV.delete(oldSessionId);
    }

    const accessToken = c.get("token");
    const refreshToken = c.get("refresh-token");
    const user = c.get("user-github");

    if (!user) {
      return c.json({ error: "User not found" }, 401);
    }

    const ttl = 60 * 60 * 24;
    const sessionId = crypto.randomUUID();
    setCookie(c, "session_id", sessionId, {
      httpOnly: true,
      secure: true,
      sameSite: "None",
      maxAge: ttl,
      path: "/",
    });

    const session = {
      user,
      accessToken,
      refreshToken,
    };

    await c.env.SESSION_STORE_KV.put(sessionId, JSON.stringify(session), {
      expirationTtl: ttl,
    });

    return c.text("Successfully logged in");
  })
  .get("/auth/logout", async (c) => {
    const session = getCookie(c, "session_id");
    if (!session) {
      return c.text("Not logged in", 401);
    }

    setCookie(c, "session_id", "", {
      httpOnly: true,
      secure: true,
      sameSite: "None",
      maxAge: 0,
    });

    await c.env.SESSION_STORE_KV.delete(session);

    return c.text("Successfully logged out");
  });

export default app;
