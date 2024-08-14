import { Hono } from "hono";
import { githubAuth } from "@hono/oauth-providers/github";

type Bindings = {
  GITHUB_CLIENT_ID: string;
  GITHUB_CLIENT_SECRET: string;
};

const app = new Hono<{ Bindings: Bindings }>();

app.use("/auth/github/login", githubAuth({}));

app.get("/auth/github/login", (c) => {
  const token = c.get("token");
  const refreshToken = c.get("refresh-token");
  const user = c.get("user-github");

  return c.json({
    token,
    refreshToken,
    user,
  });
});

export default app;
