from datetime import datetime
from typing import Callable
from uuid import UUID

import structlog
from fastapi import Cookie, Depends, HTTPException, Request
from jose import JWTError, jwt
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.config import settings
from app.database import get_db
from app.models.user import User
from app.schemas.auth import TokenPayload

logger = structlog.get_logger()

ALGORITHM = "HS256"


def create_access_token(user_id: UUID, org_id: UUID, role: str, email: str) -> str:
    expire = datetime.utcnow().timestamp() + (settings.JWT_EXPIRE_HOURS * 3600)
    payload = {
        "sub": str(user_id),
        "org_id": str(org_id),
        "role": role,
        "email": email,
        "exp": int(expire),
    }
    return jwt.encode(payload, settings.JWT_SECRET, algorithm=ALGORITHM)


def decode_token(token: str) -> TokenPayload:
    try:
        payload = jwt.decode(token, settings.JWT_SECRET, algorithms=[ALGORITHM])
        return TokenPayload(**payload)
    except JWTError as e:
        raise HTTPException(status_code=401, detail="Invalid or expired token") from e


async def get_current_user(
    request: Request,
    access_token: str | None = Cookie(default=None),
    db: AsyncSession = Depends(get_db),
) -> User:
    """Extract and validate JWT from cookie, return the User object."""
    if not access_token:
        raise HTTPException(status_code=401, detail="Not authenticated")

    token_data = decode_token(access_token)

    stmt = select(User).where(User.id == UUID(token_data.sub), User.deleted_at.is_(None))
    result = await db.execute(stmt)
    user = result.scalar_one_or_none()

    if not user:
        raise HTTPException(status_code=401, detail="User not found")

    # Attach org_id to request state for convenience
    request.state.org_id = user.org_id
    request.state.user_id = user.id
    return user


async def get_current_org_scope(
    user: User = Depends(get_current_user),
) -> tuple[User, UUID]:
    """Returns (user, org_id) — used by every org-scoped endpoint."""
    return user, user.org_id


def require_role(*allowed_roles: str) -> Callable:
    """FastAPI dependency that checks user role."""

    async def role_checker(user: User = Depends(get_current_user)) -> User:
        if user.role not in allowed_roles:
            raise HTTPException(status_code=403, detail="Insufficient permissions")
        return user

    return role_checker
