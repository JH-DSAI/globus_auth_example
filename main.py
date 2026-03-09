"""FastAPI prototype demonstrating OAuth 2.0 login via authlib."""

import json
import logging
import os
import secrets
import time
from functools import lru_cache
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
with Path("oidc_providers.json").open() as f:
    oidc_providers = json.load(f)

oauth = OAuth()

for provider in oidc_providers:
    if (
        not oidc_providers[provider]["client_id"]
        or not oidc_providers[provider]["client_secret"]
    ):
        logger.warning(
            f"Missing client_id or client_secret for {provider}. Did you forget to set them in oidc_providers.json?"
        )
        continue

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
    return e


async def get_current_user(request: Request) -> dict:
    """Helper for protecting routess that require authorization."""
    # Are we currently logged in?
    if not (token := request.session.get(USER_TOKEN_KEY)):
        raise HTTPException(status_code=401)

    # check if token has expired or will expire within the next minute
    expires_at = token.get("exp")
    is_expired = expires_at and time.time() > expires_at - 60

    if is_expired:
        try:
            # get the current provider
            provider = request.session.get(CURRENT_PROVIDER_KEY)
            client = oauth.create_client(provider)

            new_token = await client.refresh_token(
                oauth._clients[provider].server_metadata_url["token_endpoint"],
                refresh_token=token.get("refresh_token"),
            )

            request.session[USER_TOKEN_KEY] = new_token.get("userinfo")
        except Exception:
            request.session.clear()
            raise HTTPException(status_code=401)

    return token


@lru_cache
def get_provider_details(metadata_url: str) -> dict:
    """Return the details for a specific provider.

    An example of the metadata url is:
        https://auth.globus.org/.well-known/openid-configuration

    Args:
        metadata_url: The URL to the provider's OIDC metadata.

    Returns:
        A dictionary containing the provider's OIDC metadata.
    """
    resp = httpx.get(metadata_url)
    resp.raise_for_status()
    return resp.json()


# ==============================================================================
# Login/Logout routes
# ==============================================================================
@app.get("/login/{provider}")
async def login(request: Request, provider: str) -> RedirectResponse:
    """Login with a specific provider."""

    # if there isn't a provcider redirect to '/'
    if not provider:
        return RedirectResponse(url="/")

    if provider not in oidc_providers:
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

    request.session[USER_TOKEN_KEY] = token.get("userinfo")

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
    user_info = request.session.get(USER_TOKEN_KEY)
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
                    for p in oidc_providers.keys()
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
def profile(user_info=Depends(get_current_user)) -> JSONResponse:
    """Protected route - returns the logged-in user's identity and token info."""
    return JSONResponse(
        {
            "user_info": user_info,
        }
    )
