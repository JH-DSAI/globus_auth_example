# globus_auth_example

A simple FastAPI prototype that demonstrates OAuth 2.0 login via [Globus Auth](https://docs.globus.org/api/auth/).

## How it works

The app implements the [OAuth 2.0 Authorization Code flow](https://docs.globus.org/api/auth/developer-guide/#obtaining-authorization):

1. **`GET /`** – Home page. Shows login status.
2. **`GET /login`** – Redirects the browser to the Globus Auth authorization endpoint with a random `state` token (CSRF protection).
3. **`GET /callback`** – Handles the redirect from Globus Auth. Validates the `state`, exchanges the authorization code for tokens via the Globus SDK, decodes the OIDC ID token for user identity claims, and stores everything in a signed session cookie.
4. **`GET /profile`** – Protected route. Returns user identity and resource-server token metadata as JSON.
5. **`GET /logout`** – Revokes the Globus access tokens and clears the session.

## Prerequisites

1. **Register a Confidential App** in the [Globus Developer Console](https://app.globus.org/settings/developers).
2. Add `http://localhost:8000/callback` as an allowed redirect URL for your app.
3. Note the **Client ID** and **Client Secret**.

## Setup

```bash
# 1. Install dependencies
uv sync

# 2. Configure environment variables
cp .env.example .env
# Edit .env with your GLOBUS_CLIENT_ID, GLOBUS_CLIENT_SECRET, and SESSION_SECRET_KEY

# 3. Run the server
uv run uvicorn main:app --reload
```

Open <http://localhost:8000> in your browser and click **Login with Globus**.

## Environment variables

| Variable              | Description                                                                                       |
|-----------------------|---------------------------------------------------------------------------------------------------|
| `GLOBUS_CLIENT_ID`    | Client ID from the Globus developer console.                                                      |
| `GLOBUS_CLIENT_SECRET`| Client secret from the Globus developer console.                                                  |
| `REDIRECT_URI`        | OAuth callback URL (default: `http://localhost:8000/callback`). Must be registered with your app. |
| `SESSION_SECRET_KEY`  | Secret key used to sign the session cookie. Use a long random value in production.                |

Generate a strong session key:

```bash
python -c "import secrets; print(secrets.token_hex(32))"
```

## Dependencies

| Package        | Purpose                                                                              |
|----------------|--------------------------------------------------------------------------------------|
| `fastapi`      | ASGI web framework.                                                                  |
| `uvicorn`      | ASGI server.                                                                         |
| `globus-sdk`   | Globus Auth OAuth2/OIDC client (primary OAuth implementation).                       |
| `authlib`      | JWT/OIDC utilities; alternative OAuth2 client for non-Globus resource servers.       |
| `itsdangerous` | Signed-cookie sessions (via Starlette's `SessionMiddleware`).                        |
| `python-dotenv`| Loads environment variables from `.env`.                                             |
| `httpx`        | HTTP client used by authlib.                                                         |