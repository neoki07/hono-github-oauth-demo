import { Context, Hono } from "hono";
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
  expirationTime: number;
};

type Session = {
  user: Partial<GitHubUser>;
  accessToken: Token;
  refreshToken: Token;
};

function getSessionStore(c: Context<{ Bindings: Bindings }>) {
  return c.env.SESSION_STORE_KV;
}

function createSessionId() {
  return crypto.randomUUID();
}

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
      return c.json({ error: { message: "Unauthorized" } }, 401);
    }

    const store = getSessionStore(c);
    const session = await getSessionFromStore(sessionId, store);
    if (!session) {
      return c.json({ error: { message: "Unauthorized" } }, 401);
    }

    if (session.accessToken.expirationTime < Date.now()) {
      return c.json({ error: { message: "Unauthorized" } }, 401);
    }

    await next();
  }
);

const app = new Hono<{ Bindings: Bindings }>();

app.use("/auth/github/login", githubAuth({}));

app
  .get("/auth/github/login", async (c) => {
    const store = getSessionStore(c);

    const accessToken = c.get("token");
    const refreshToken = c.get("refresh-token");
    const user = c.get("user-github");

    if (!user || !accessToken || !refreshToken) {
      return c.json({ error: { message: "Failed to login" } }, 400);
    }

    const oldSessionId = getCookie(c, SESSION_ID_COOKIE_KEY);
    if (oldSessionId) {
      await deleteSessionFromStore(oldSessionId, store);
    }

    const newSessionId = createSessionId();
    setCookie(c, SESSION_ID_COOKIE_KEY, newSessionId, {
      httpOnly: true,
      secure: true,
      sameSite: "None",
      maxAge: SESSION_TTL,
      path: "/",
    });

    const session: Session = {
      user,
      accessToken: {
        token: accessToken.token,
        expirationTime: Date.now() + accessToken.expires_in * 1000,
      },
      refreshToken: {
        token: refreshToken.token,
        expirationTime: Date.now() + refreshToken.expires_in * 1000,
      },
    };

    await setSessionToStore(newSessionId, session, store, {
      expirationTtl: SESSION_TTL,
    });

    return c.json({ message: "Successfully logged in" });
  })
  .get("/auth/logout", async (c) => {
    const store = getSessionStore(c);

    const sessionId = getCookie(c, SESSION_ID_COOKIE_KEY);
    if (!sessionId) {
      return c.json({ error: { message: "Not logged in" } }, 400);
    }

    deleteCookie(c, SESSION_ID_COOKIE_KEY);
    await deleteSessionFromStore(sessionId, store);

    return c.json({ message: "Successfully logged out" });
  })
  .get("/me", authMiddleware, async (c) => {
    const store = getSessionStore(c);

    const sessionId = getCookie(c, SESSION_ID_COOKIE_KEY)!;
    const session = await getSessionFromStore(sessionId, store);
    if (!session?.user) {
      return c.json({ error: { message: "Failed to get user" } }, 400);
    }

    return c.json({ user: session.user });
  });

export default app;
