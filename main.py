"""FastAPI prototype demonstrating OAuth 2.0 login via authlib."""

import json
import logging
import os
import secrets
from contextvars import ContextVar
from pathlib import Path

from dotenv import load_dotenv
from fastapi import Depends, FastAPI, HTTPException, Request
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse
from starlette.middleware.sessions import SessionMiddleware
from authlib.integrations.starlette_client import OAuth, OAuthError

logger = logging.getLogger(__name__)

load_dotenv()

# The following scopes are requested from the provider
# openid: enables the ID token
# profile: adds name/preferred_username claims
# email: adds email claim
REQUESTED_SCOPES = "openid profile email"
# This is the key used to store the user token in the session
USER_TOKEN_KEY = "user_token"
# This is the key used to store the current provider in the session
CURRENT_PROVIDER_KEY = "oauth_provider"

app = FastAPI(title="Globus OAuth Login Prototype")

# ==============================================================================
# Configure OAuth Providers
# ==============================================================================
request_var: ContextVar[Request] = ContextVar("request")
async def _update_token(name, token, refresh_token=None, access_token=None):
    """Update the token in the session."""
    request = request_var.get()
    request.session[USER_TOKEN_KEY] = token


with Path("oidc_providers.json").open() as f:
    oidc_providers = json.load(f)

oauth = OAuth()
valid_providers = set()
for provider in oidc_providers:
    if (
        not oidc_providers[provider]["client_id"]
        or not oidc_providers[provider]["client_secret"]
    ):
        logger.warning(
            f"Missing client_id or client_secret for {provider}. Did you forget to set them in oidc_providers.json?"
        )
        continue

    valid_providers.add(provider)
    oauth.register(
        name=provider,
        client_id=oidc_providers[provider]["client_id"],
        client_secret=oidc_providers[provider]["client_secret"],
        server_metadata_url=oidc_providers[provider]["metadata_url"],
        client_kwargs={
            "scope": REQUESTED_SCOPES,
        },
    )

# ==============================================================================
# Configure session middleware
# ==============================================================================
if not (SESSION_SECRET_KEY := os.environ.get("SESSION_SECRET_KEY", "")):
    SESSION_SECRET_KEY = secrets.token_hex(32)
    logger.warning(
        "SESSION_SECRET_KEY is not set. Using a random key - sessions will be "
        "invalidated on every restart and won't work across multiple instances. "
        "Set SESSION_SECRET_KEY in your .env file for persistent sessions."
    )

# Starlette's SessionMiddleware stores session data in a signed cookie.
# Set https_only=True and a strong SESSION_SECRET_KEY in production.
app.add_middleware(
    SessionMiddleware,
    secret_key=SESSION_SECRET_KEY,
    https_only=os.getenv("SESSION_COOKIE_SECURE", "true").lower() in ("true", "1", "t"),
)


# ==============================================================================
# Configure authentication helpers
# ==============================================================================
@app.exception_handler(HTTPException)
async def auth_exception_handler(request: Request, e: HTTPException):
    """Routes authorization exceptions to where login happens, otherwises reraise."""
    if e.status_code == 401:
        return RedirectResponse(url="/")
    raise e


async def get_current_user(request: Request) -> dict:
    """Helper for protecting routess that require authorization."""
    request_var.set(request)
    token = request.session.get(USER_TOKEN_KEY)
    if not token:
        raise HTTPException(status_code=401)

    provider = request.session.get(CURRENT_PROVIDER_KEY)
    if not provider:
        raise HTTPException(status_code=401, detail="No provider found in session")

    client = oauth.create_client(provider)

    try:
        # It uses the 'update_token' callback to save the new credentials.
        user = await client.userinfo(token=token)
        return user
    except Exception:
        # If refresh fails (e.g., refresh token is revoked/expired), clear session
        request.session.clear()
        raise HTTPException(status_code=401)

# ==============================================================================
# Login/Logout routes
# ==============================================================================
@app.get("/login/{provider}")
async def login(request: Request, provider: str) -> RedirectResponse:
    """Login with a specific provider."""

    # FastAPI ensures that the provider path parameter is present and non-empty.

    if provider not in valid_providers:
        raise HTTPException(
            status_code=400,
            detail=f"Unrecognized provider: {provider}",
        )

    # store the provider in the session so we can retrieve it in the `callback`
    request.session[CURRENT_PROVIDER_KEY] = provider

    # authlib will generate a random state and save it in the session as
    # '_state_{provider}_...
    redirect_uri = request.url_for("callback")
    client = oauth.create_client(provider)
    redirect = await client.authorize_redirect(
        request,
        redirect_uri,
    )

    return redirect


@app.get("/callback")
async def callback(request: Request) -> RedirectResponse:
    """Callback for OIDC providers after authenticating."""
    # Retrieve the name from the session
    if not (provider := request.session.get(CURRENT_PROVIDER_KEY)):
        raise HTTPException(status_code=400, detail="No provider found in session")

    try:
        # confirm access token using `state`
        token = await oauth.create_client(provider).authorize_access_token(request)
    except OAuthError as e:
        raise HTTPException(
            status_code=400, detail=f"CSRF Validation Failed: {e.error}"
        )

    request.session[USER_TOKEN_KEY] = token

    return RedirectResponse(url="/")


@app.get("/logout")
def logout(request: Request) -> RedirectResponse:
    """Remove the user's token from the session."""
    request.session.pop(USER_TOKEN_KEY, None)
    return RedirectResponse(url="/")


# ==============================================================================
# Unprotected routes
# ==============================================================================
@app.get("/", response_class=HTMLResponse)
def home(request: Request) -> HTMLResponse:
    """Home page - shows the current login status."""
    token = request.session.get(USER_TOKEN_KEY)
    if token and (userinfo := token.get("userinfo")):
        name = userinfo.get("name") or userinfo.get("preferred_username", "Unknown")
        email = userinfo.get("email", "")
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
        html = (
            """<!DOCTYPE html>
<html lang="en">
<head><meta charset="utf-8"><title>Globus Auth Example</title></head>
<body>
  <h1>Globus OAuth Login Prototype</h1>
  <p>Not logged in.</p>
"""
            + "\n".join(
                [
                    f'<a href="/login/{p}"><button>Login with {p.capitalize()}</button></a>'
                    for p in valid_providers
                ]
            )
            + """
</body>
</html>"""
        )
    return HTMLResponse(content=html)


# ==============================================================================
# Protected routes
# ==============================================================================
@app.get("/profile", response_model=None)
async def profile(user_info=Depends(get_current_user)) -> JSONResponse:
    """Protected route - returns the logged-in user's identity and token info."""
    return JSONResponse(
        {
            "user_info": user_info,
        }
    )
