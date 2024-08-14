import { Hono } from "hono";
import { githubAuth, GitHubUser } from "@hono/oauth-providers/github";
import { getCookie, setCookie, deleteCookie } from "hono/cookie";
import { createMiddleware } from "hono/factory";

const SESSION_TTL = 60 * 60 * 24;
const SESSION_ID_COOKIE_KEY = "session_id";

type Bindings = {
  SESSION_STORE_KV: KVNamespace;
};

type Token = {
  token: string;
  expires_in: number;
};

type Session = {
  user: Partial<GitHubUser>;
  accessToken: Token;
  refreshToken: Token;
};

async function getSessionFromStore(
  sessionId: string,
  store: KVNamespace<string>
): Promise<Session | undefined> {
  const session = await store.get(sessionId);
  return session ? JSON.parse(session) : undefined;
}

async function setSessionToStore(
  sessionId: string,
  session: Session,
  store: KVNamespace<string>,
  options?: KVNamespacePutOptions
) {
  await store.put(sessionId, JSON.stringify(session), options);
}

async function deleteSessionFromStore(
  sessionId: string,
  store: KVNamespace<string>
) {
  await store.delete(sessionId);
}

const authMiddleware = createMiddleware<{ Bindings: Bindings }>(
  async (c, next) => {
    const sessionId = getCookie(c, SESSION_ID_COOKIE_KEY);
    if (!sessionId) {
      return c.text("Not logged in", 401);
    }

    const store = c.env.SESSION_STORE_KV;
    const session = await getSessionFromStore(sessionId, store);
    if (!session) {
      return c.text("Not logged in", 401);
    }

    await next();
  }
);

const app = new Hono<{ Bindings: Bindings }>();

app.use("/auth/github/login", githubAuth({}));

app
  .get("/auth/github/login", async (c) => {
    const store = c.env.SESSION_STORE_KV;

    const oldSessionId = getCookie(c, SESSION_ID_COOKIE_KEY);
    if (oldSessionId) {
      deleteCookie(c, SESSION_ID_COOKIE_KEY);
      await deleteSessionFromStore(oldSessionId, store);
    }

    const accessToken = c.get("token");
    const refreshToken = c.get("refresh-token");
    const user = c.get("user-github");

    if (!user) {
      return c.json({ error: "User not found" }, 401);
    }

    if (!accessToken || !refreshToken) {
      return c.json({ error: "Access token or refresh token not found" }, 401);
    }

    const sessionId = crypto.randomUUID();
    setCookie(c, SESSION_ID_COOKIE_KEY, sessionId, {
      httpOnly: true,
      secure: true,
      sameSite: "None",
      maxAge: SESSION_TTL,
      path: "/",
    });

    const session: Session = {
      user,
      accessToken,
      refreshToken,
    };

    await setSessionToStore(sessionId, session, store, {
      expirationTtl: SESSION_TTL,
    });

    return c.text("Successfully logged in");
  })
  .get("/auth/logout", async (c) => {
    const store = c.env.SESSION_STORE_KV;

    const session = getCookie(c, SESSION_ID_COOKIE_KEY);
    if (!session) {
      return c.text("Not logged in", 401);
    }

    deleteCookie(c, SESSION_ID_COOKIE_KEY);
    await deleteSessionFromStore(session, store);

    return c.text("Successfully logged out");
  })
  .get("/me", authMiddleware, async (c) => {
    const store = c.env.SESSION_STORE_KV;

    const sessionId = getCookie(c, SESSION_ID_COOKIE_KEY)!;
    const session = await getSessionFromStore(sessionId, store);
    if (!session?.user) {
      return c.text("Not logged in", 401);
    }

    return c.json({ user: session.user });
  });

export default app;
