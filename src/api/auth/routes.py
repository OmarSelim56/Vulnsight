from sqlite3 import IntegrityError

from fastapi import APIRouter, Depends, HTTPException, status

from src.api.auth.dependencies import get_current_user, require_roles
from src.api.auth.schemas import LoginRequest, RegisterRequest, TokenResponse, UserInfo
from src.api.auth.security import build_access_token
from src.db.auth_repository import AuthRepository, verify_password

router = APIRouter(prefix="/api/v1/auth", tags=["auth"])
auth_repository: AuthRepository | None = None


def set_auth_repository(repository: AuthRepository):
    global auth_repository
    auth_repository = repository


@router.post("/login", response_model=TokenResponse)
def login(payload: LoginRequest):
    if auth_repository is None:
        raise HTTPException(status_code=500, detail="Auth repository is not configured")
    user = auth_repository.get_user_by_username(payload.username.strip())
    if not user or not verify_password(payload.password, user["password_hash"]):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid credentials")
    if not user.get("is_active"):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Account is inactive")
    roles = auth_repository.get_user_roles(user["id"])
    token, expires_at = build_access_token(user_id=user["id"], username=user["username"], roles=roles)
    return TokenResponse(access_token=token, expires_at=expires_at)


@router.post(
    "/register",
    response_model=UserInfo,
    dependencies=[Depends(require_roles("admin"))],
)
def register(payload: RegisterRequest):
    if auth_repository is None:
        raise HTTPException(status_code=500, detail="Auth repository is not configured")
    username = payload.username.strip()
    # Single-role policy: every user has exactly one role.
    if len(payload.roles) != 1:
        raise HTTPException(status_code=400, detail="exactly one role is required")
    try:
        user_id = auth_repository.create_user(
            username=username,
            password=payload.password,
            roles=payload.roles,
        )
    except IntegrityError as exc:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="Username already exists") from exc
    roles = auth_repository.get_user_roles(user_id)
    return UserInfo(id=user_id, username=username, roles=roles)


@router.get("/me", response_model=UserInfo)
def me(current_user=Depends(get_current_user)):
    return UserInfo(
        id=current_user["id"],
        username=current_user["username"],
        roles=current_user["roles"],
    )
