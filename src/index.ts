import { Hono } from "hono";
import { z } from "zod";
import { zValidator } from "@hono/zod-validator";

type Bindings = {
  GITHUB_CLIENT_ID: string;
  GITHUB_CLIENT_SECRET: string;
};

interface GitHubAccessTokenRequest {
  access_token?: string;
  scope?: string;
  token_type?: string;
}

const app = new Hono<{ Bindings: Bindings }>()
  .get("/login", (c) => {
    const clientId = c.env.GITHUB_CLIENT_ID;
    const redirectUrl = `https://github.com/login/oauth/authorize?client_id=${clientId}&state=randomstring`;
    return c.redirect(redirectUrl, 302);
  })
  .get(
    "/callback",
    zValidator(
      "query",
      z.object({
        code: z.string(),
        state: z.string(),
      })
    ),
    async (c) => {
      const { code } = c.req.valid("query");

      const clientId = c.env.GITHUB_CLIENT_ID;
      const clientSecret = c.env.GITHUB_CLIENT_SECRET;

      const response = await fetch(
        "https://github.com/login/oauth/access_token",
        {
          method: "POST",
          headers: {
            "Content-Type": "application/json",
            Accept: "application/json",
          },
          body: JSON.stringify({
            client_id: clientId,
            client_secret: clientSecret,
            code,
          }),
        }
      );

      if (!response.ok) {
        return c.text("Failed to get an access token", 500);
      }

      const data: GitHubAccessTokenRequest = await response.json();
      if (!data.access_token) {
        return c.text("Failed to get an access token", 500);
      }

      const accessToken = data.access_token;

      const userResponse = await fetch("https://api.github.com/user", {
        headers: {
          Authorization: `Bearer ${accessToken}`,
          "User-Agent": "hono-github-oauth-demo",
        },
      });
      if (!userResponse.ok) {
        return c.text("Failed to get user data", 500);
      }

      const userData: { [key in string]?: string } = await userResponse.json();
      return c.json(userData);
    }
  );

export default app;
