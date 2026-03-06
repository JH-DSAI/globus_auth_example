"""FastAPI prototype demonstrating OAuth 2.0 login via Globus Auth."""

import logging
import os
import secrets

import globus_sdk
from dotenv import load_dotenv
from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse
from starlette.middleware.sessions import SessionMiddleware

logger = logging.getLogger(__name__)

load_dotenv()

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------
GLOBUS_CLIENT_ID: str = os.environ.get("GLOBUS_CLIENT_ID", "")
GLOBUS_CLIENT_SECRET: str = os.environ.get("GLOBUS_CLIENT_SECRET", "")
REDIRECT_URI: str = os.environ.get("REDIRECT_URI", "http://localhost:8000/callback")
SESSION_SECRET_KEY: str = os.environ.get("SESSION_SECRET_KEY", "")
if not SESSION_SECRET_KEY:
    SESSION_SECRET_KEY = secrets.token_hex(32)
    logger.warning(
        "SESSION_SECRET_KEY is not set. Using a random key – sessions will be "
        "invalidated on every restart and won't work across multiple instances. "
        "Set SESSION_SECRET_KEY in your .env file for persistent sessions."
    )

# Globus Auth scopes - ``openid`` enables the ID token; ``profile`` and
# ``email`` add name/preferred_username and email claims respectively.
REQUESTED_SCOPES: str = "openid profile email"

app = FastAPI(title="Globus OAuth Login Prototype")

# Starlette's SessionMiddleware stores session data in a signed cookie.
# Set https_only=True and a strong SESSION_SECRET_KEY in production.
app.add_middleware(
    SessionMiddleware,
    secret_key=SESSION_SECRET_KEY,
    https_only=os.getenv("SESSION_COOKIE_HTTPS_ONLY", "true").lower() in ("true", "1", "t"),
)


def _build_auth_client() -> globus_sdk.ConfidentialAppAuthClient:
    """Return a configured Globus :class:`ConfidentialAppAuthClient`.

    Raises :class:`~fastapi.HTTPException` (500) if the required environment
    variables have not been set.
    """
    if not GLOBUS_CLIENT_ID or not GLOBUS_CLIENT_SECRET:
        raise HTTPException(
            status_code=500,
            detail=(
                "GLOBUS_CLIENT_ID and GLOBUS_CLIENT_SECRET must be set. "
                "Copy .env.example to .env and fill in your credentials."
            ),
        )
    return globus_sdk.ConfidentialAppAuthClient(
        client_id=GLOBUS_CLIENT_ID,
        client_secret=GLOBUS_CLIENT_SECRET,
    )


@app.get("/", response_class=HTMLResponse)
def home(request: Request) -> HTMLResponse:
    """Home page - shows the current login status."""
    user_info = request.session.get("user_info")
    if user_info:
        name = user_info.get("name") or user_info.get("preferred_username", "Unknown")
        email = user_info.get("email", "")
        html = f"""<!DOCTYPE html>
<html lang="en">
<head><meta charset="utf-8"><title>Globus Auth Example</title></head>
<body>
  <h1>Globus OAuth Login Prototype</h1>
  <p>&#x2705; Logged in as <strong>{name}</strong> ({email})</p>
  <ul>
    <li><a href="/profile">View profile (JSON)</a></li>
    <li><a href="/logout">Logout</a></li>
  </ul>
</body>
</html>"""
    else:
        html = """<!DOCTYPE html>
<html lang="en">
<head><meta charset="utf-8"><title>Globus Auth Example</title></head>
<body>
  <h1>Globus OAuth Login Prototype</h1>
  <p>Not logged in.</p>
  <a href="/login"><button>Login with Globus</button></a>
</body>
</html>"""
    return HTMLResponse(content=html)


@app.get("/login")
def login(request: Request) -> RedirectResponse:
    """Begin the Globus OAuth 2.0 Authorization Code flow.

    Generates a random ``state`` token for CSRF protection, stores it in the
    session, then redirects the browser to the Globus Auth authorization
    endpoint.
    """
    state = secrets.token_urlsafe(32)

    auth_client = _build_auth_client()
    auth_client.oauth2_start_flow(
        redirect_uri=REDIRECT_URI,
        requested_scopes=REQUESTED_SCOPES,
        state=state,
    )

    response = RedirectResponse(url=str(auth_client.oauth2_get_authorize_url()))
    # Store the state in a cookie
    # https://www.starlette.dev/responses/#set-cookie
    response.set_cookie(
        "oauth_state",
        state,
        max_age=int(os.environ.get("SESSION_COOKIE_MAX_AGE_SECONDS", 3600)),
        path="/",
        secure=os.environ.get("SESSION_COOKIE_SECURE", "true").lower() in ("true", "1", "t"),
        httponly=True,
        samesite=os.environ.get("SESSION_COOKIE_SAMESITE", "lax")
    )

    return response

@app.get("/callback")
def callback(
    request: Request,
    code: str | None = None,
    state: str | None = None,
) -> RedirectResponse:
    """OAuth 2.0 callback - exchange the authorization code for tokens.

    Validates the ``state`` parameter against the value stored in the session
    to prevent CSRF attacks, then exchanges the authorization code for tokens
    and stores the decoded identity claims and token metadata in the session.
    """
    if not code:
        raise HTTPException(status_code=400, detail="Missing authorization code")

    stored_state = request.cookies.get("oauth_state")

    print("state: ", state)
    print("stored_state: ", stored_state)

    if not state or state != stored_state:
        raise HTTPException(
            status_code=400,
            detail="Invalid or missing OAuth state - possible CSRF attempt",
        )

    auth_client = _build_auth_client()
    # https://docs.globus.org/api/auth/developer-guide/#obtaining-authorization
    # src:
    # https://github.com/globus/globus-sdk-python/blob/73e9acd4b74e85a73aeccd5d8221436758a46bef/src/globus_sdk/services/auth/client/native_client.py#L56
    auth_client.oauth2_start_flow(
        redirect_uri=REDIRECT_URI,
        requested_scopes=REQUESTED_SCOPES,
    )

    token_response = auth_client.oauth2_exchange_code_for_tokens(code)

    # Decode the OIDC ID token to obtain user identity claims.
    # The globus-sdk verifies the token signature automatically.
    id_token_claims = token_response.decode_id_token()
    request.session["user_info"] = {
        "sub": id_token_claims.get("sub"),
        "name": id_token_claims.get("name"),
        "email": id_token_claims.get("email"),
        "preferred_username": id_token_claims.get("preferred_username"),
    }

    # Persist token metadata keyed by resource server for later use.
    request.session["tokens"] = {
        rs: {
            "access_token": data["access_token"],
            "expires_at_seconds": data["expires_at_seconds"],
            "scope": data["scope"],
            "token_type": data["token_type"],
            **(
                {"refresh_token": data["refresh_token"]}
                if data.get("refresh_token")
                else {}
            ),
        }
        for rs, data in token_response.by_resource_server.items()
    }

    return RedirectResponse(url="/")


@app.get("/profile", response_model=None)
def profile(request: Request) -> JSONResponse | RedirectResponse:
    """Protected route – returns the logged-in user's identity and token info.

    Redirects to ``/login`` when no authenticated session exists.
    """
    if not request.session.get("user_info"):
        return RedirectResponse(url="/login")

    return JSONResponse(
        {
            "user_info": request.session["user_info"],
            "resource_servers": list(request.session.get("tokens", {}).keys()),
        }
    )


@app.get("/logout")
def logout(request: Request) -> RedirectResponse:
    """Revoke Globus access tokens and clear the local session."""
    tokens = request.session.get("tokens", {})
    if tokens and GLOBUS_CLIENT_ID and GLOBUS_CLIENT_SECRET:
        auth_client = _build_auth_client()
        for _rs, token_data in tokens.items():
            try:
                auth_client.oauth2_revoke_token(token_data["access_token"])
            except Exception:
                pass  # best-effort revocation; do not block logout on failure

    request.session.clear()
    return RedirectResponse(url="/")
