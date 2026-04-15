"""
SIGINTX — JWT Authentication
v3.0.0
"""
import os
import logging
from datetime import datetime, timedelta, timezone
from typing import Optional

import jwt
from jwt.exceptions import PyJWTError
from passlib.context import CryptContext
from fastapi import Depends, HTTPException, status
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, update

from database import User, AuditLog, get_db

logger = logging.getLogger(__name__)

# ── Configuration ─────────────────────────────────────────────────────────────

SECRET_KEY: str = os.getenv("JWT_SECRET", "")

if not SECRET_KEY:
    # In dev mode (AUTH_DISABLED=true) a missing secret is tolerated —
    # tokens are never validated so the key is unused.
    # In any other context, refuse to start.
    _auth_disabled_env = os.getenv("AUTH_DISABLED", "false").lower() == "true"
    if not _auth_disabled_env:
        raise RuntimeError(
            "JWT_SECRET environment variable is not set. "
            "Generate one with: openssl rand -hex 32\n"
            "To run without auth for local dev only, also set AUTH_DISABLED=true."
        )
    # Assign a throw-away value so the app starts; it will never be used for
    # real token validation since AUTH_DISABLED=true skips all JWT checks.
    import secrets as _secrets
    SECRET_KEY = _secrets.token_hex(32)
    logger.warning(
        "JWT_SECRET not set — using a temporary random key for this session. "
        "Tokens will not survive a restart. Set AUTH_DISABLED=false in production."
    )

ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_HOURS: int = 24 * 7  # 7 days

# AUTH_DISABLED=true bypasses token validation (local dev only).
# Default is FALSE — auth is ON unless explicitly disabled.
AUTH_DISABLED: bool = os.getenv("AUTH_DISABLED", "false").lower() == "true"

if AUTH_DISABLED:
    logger.warning(
        "AUTH_DISABLED=true — all endpoints are open without authentication. "
        "Never run with this setting in production."
    )

# ── Crypto helpers ────────────────────────────────────────────────────────────

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
bearer_scheme = HTTPBearer(auto_error=False)


def hash_password(password: str) -> str:
    """Return a bcrypt hash of *password*."""
    return pwd_context.hash(password)


def verify_password(plain: str, hashed: str) -> bool:
    """Return True if *plain* matches the stored *hashed* password."""
    return pwd_context.verify(plain, hashed)


def create_access_token(
    data: dict,
    expires_delta: Optional[timedelta] = None,
) -> str:
    """
    Encode *data* as a signed JWT.

    If *expires_delta* is not supplied the token expires after
    ACCESS_TOKEN_EXPIRE_HOURS hours.
    """
    to_encode = data.copy()
    expire = datetime.now(timezone.utc) + (
        expires_delta if expires_delta is not None
        else timedelta(hours=ACCESS_TOKEN_EXPIRE_HOURS)
    )
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)


# ── Credentials exception helper ──────────────────────────────────────────────

def _credentials_exception(detail: str = "Could not validate credentials") -> HTTPException:
    return HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail=detail,
        headers={"WWW-Authenticate": "Bearer"},
    )


# ── FastAPI dependencies ──────────────────────────────────────────────────────

async def get_current_user(
    credentials: Optional[HTTPAuthorizationCredentials] = Depends(bearer_scheme),
    db: AsyncSession = Depends(get_db),
) -> User:
    """
    Validate the Bearer JWT and return the corresponding User row.

    Raises HTTP 401 if the token is missing, expired, or invalid.
    When AUTH_DISABLED=true the first user in the database is returned
    without checking a token (local development only).
    """
    if AUTH_DISABLED:
        result = await db.execute(select(User).limit(1))
        user = result.scalar_one_or_none()
        if user is None:
            # No users at all — return a synthetic user object (e.g. first boot)
            return User(id=0, username="admin", hashed_password="")
        return user

    if credentials is None:
        raise _credentials_exception("No authentication token provided")

    token = credentials.credentials
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
    except PyJWTError as exc:
        logger.debug("JWT decode failed: %s", exc)
        raise _credentials_exception() from exc

    username: Optional[str] = payload.get("sub")
    if username is None:
        raise _credentials_exception("Token payload missing 'sub' claim")

    result = await db.execute(select(User).where(User.username == username))
    user = result.scalar_one_or_none()
    if user is None:
        raise _credentials_exception(f"User '{username}' not found")

    return user


async def get_optional_user(
    credentials: Optional[HTTPAuthorizationCredentials] = Depends(bearer_scheme),
    db: AsyncSession = Depends(get_db),
) -> Optional[User]:
    """
    Like get_current_user but returns *None* instead of raising when there is
    no token or the token is invalid.  Useful for endpoints that behave
    differently when authenticated but are publicly accessible.
    """
    if AUTH_DISABLED:
        result = await db.execute(select(User).limit(1))
        return result.scalar_one_or_none()

    if credentials is None:
        return None

    try:
        return await get_current_user(credentials=credentials, db=db)
    except HTTPException:
        return None


# ── Login helper ──────────────────────────────────────────────────────────────

async def authenticate_user(
    username: str,
    password: str,
    db: AsyncSession,
    ip_address: Optional[str] = None,
) -> Optional[User]:
    """
    Verify *username* / *password* against the database.

    On success:
    - Updates User.last_login.
    - Writes an "auth.login" AuditLog entry.

    Returns the User on success, or None on failure.
    """
    result = await db.execute(select(User).where(User.username == username))
    user = result.scalar_one_or_none()

    if user is None or not verify_password(password, user.hashed_password):
        # Write failed-login audit entry
        db.add(AuditLog(
            action="auth.login.failed",
            actor=username,
            details=f'{{"reason": "bad credentials"}}',
            ip_address=ip_address,
        ))
        await db.commit()
        return None

    # Update last_login timestamp
    await db.execute(
        update(User)
        .where(User.id == user.id)
        .values(last_login=datetime.utcnow())
    )
    db.add(AuditLog(
        action="auth.login",
        actor=username,
        ip_address=ip_address,
    ))
    await db.commit()
    await db.refresh(user)
    return user
