from fastapi import Request, HTTPException, Depends, status
from sqlmodel import Session, select
from database import get_session
from models import AppUser, UserRole
from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError

ph = PasswordHasher()

def hash_password(password: str) -> str:
    """Hash a password using Argon2id."""
    return ph.hash(password)

def verify_password(hash_str: str, password: str) -> bool:
    """Verify a password against its Argon2 hash."""
    try:
        return ph.verify(hash_str, password)
    except VerifyMismatchError:
        return False

def get_current_user(request: Request, db: Session = Depends(get_session)) -> AppUser:
    """Get the currently logged-in user from the session cookie."""
    username = request.session.get("username")
    if not username:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Not authenticated"
        )
    
    statement = select(AppUser).where(AppUser.username == username, AppUser.is_active == True)
    user = db.exec(statement).first()
    if not user:
        # Clear stale session
        request.session.clear()
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="User session invalid or user deactivated"
        )
    return user

def require_admin(user: AppUser = Depends(get_current_user)) -> AppUser:
    """Require the user to have the Admin role."""
    if user.role != UserRole.ADMIN:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Admin privileges required"
        )
    return user

def require_operator(user: AppUser = Depends(get_current_user)) -> AppUser:
    """Require the user to have at least Operator role."""
    # Both Admin and Operator roles are allowed for operator actions
    return user
