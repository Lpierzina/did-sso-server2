"""
DID SSO Server - Main application with encrypted file system and permission management.
"""

from fastapi import FastAPI, HTTPException, Depends, status
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from pydantic import BaseModel
from typing import Optional, Dict, Any, List
import jwt
import os
from datetime import datetime, timedelta
import uvicorn

from crypto_fs import EncryptedFileSystem
from permissions import PermissionManager, Permission, Role


# Configuration
SECRET_KEY = os.getenv("SECRET_KEY", "your-secret-key-change-in-production")
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30
MASTER_ENCRYPTION_KEY = os.getenv("MASTER_KEY", "default-master-key-change-in-production")

# Initialize components
app = FastAPI(
    title="DID SSO Server",
    description="Decentralized Identity SSO Server with encrypted file system and permission management",
    version="1.0.0"
)
security = HTTPBearer()
crypto_fs = EncryptedFileSystem(MASTER_ENCRYPTION_KEY)
permission_manager = PermissionManager()


# Pydantic models
class WalletData(BaseModel):
    """Model for wallet data."""
    wallet_id: str
    owner: str
    did_document: Dict[str, Any]
    certificates: List[Dict[str, Any]] = []
    metadata: Dict[str, Any] = {}


class UserCreate(BaseModel):
    """Model for creating a new user."""
    username: str
    role: str = "user"


class PermissionGrant(BaseModel):
    """Model for granting permissions."""
    user_id: str
    permission: str
    wallet_id: Optional[str] = None


class Token(BaseModel):
    """Model for JWT token response."""
    access_token: str
    token_type: str = "bearer"


class UserInfo(BaseModel):
    """Model for user information."""
    user_id: str
    username: str


# Authentication functions
def create_access_token(data: Dict[str, Any], expires_delta: Optional[timedelta] = None):
    """Create JWT access token."""
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt


def verify_token(credentials: HTTPAuthorizationCredentials = Depends(security)) -> str:
    """Verify JWT token and return user_id."""
    try:
        payload = jwt.decode(credentials.credentials, SECRET_KEY, algorithms=[ALGORITHM])
        user_id: str = payload.get("sub")
        if user_id is None:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid authentication credentials",
                headers={"WWW-Authenticate": "Bearer"},
            )
        
        # Update last access time
        permission_manager.update_last_access(user_id)
        return user_id
    except jwt.PyJWTError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid authentication credentials",
            headers={"WWW-Authenticate": "Bearer"},
        )


def require_permission(permission: Permission, wallet_id: Optional[str] = None):
    """Dependency to require specific permission."""
    def _check_permission(user_id: str = Depends(verify_token)):
        if not permission_manager.check_permission(user_id, permission, wallet_id):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Insufficient permissions: {permission.value} required"
            )
        return user_id
    return _check_permission


# API Endpoints

@app.get("/")
async def root():
    """Root endpoint with API information."""
    return {
        "message": "DID SSO Server with Encrypted File System",
        "version": "1.0.0",
        "features": [
            "Encrypted ADCS storage",
            "Permission-based access control", 
            "JWT authentication",
            "DID document management"
        ]
    }


@app.post("/auth/create-user", response_model=Dict[str, str])
async def create_user(user_data: UserCreate, admin_user: str = Depends(require_permission(Permission.ADMIN))):
    """Create a new user (admin only)."""
    try:
        role = Role(user_data.role.lower())
    except ValueError:
        raise HTTPException(status_code=400, detail="Invalid role")
    
    user_id = permission_manager.create_user(user_data.username, role)
    return {"user_id": user_id, "username": user_data.username, "role": role.value}


@app.post("/auth/login", response_model=Token)
async def login(user_id: str):
    """Login with user_id (simplified for demo - in production use proper authentication)."""
    if user_id not in permission_manager.users:
        raise HTTPException(status_code=404, detail="User not found")
    
    access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = create_access_token(
        data={"sub": user_id}, expires_delta=access_token_expires
    )
    return {"access_token": access_token, "token_type": "bearer"}


@app.get("/auth/me", response_model=UserInfo)
async def get_current_user(user_id: str = Depends(verify_token)):
    """Get current user information."""
    user = permission_manager.users.get(user_id)
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    
    return {"user_id": user_id, "username": user.username}


@app.post("/wallets/{wallet_id}")
async def create_wallet(
    wallet_id: str, 
    wallet_data: WalletData,
    user_id: str = Depends(require_permission(Permission.WRITE))
):
    """Create or update encrypted wallet data."""
    if crypto_fs.wallet_exists(wallet_id):
        # Check if user has permission to write to this specific wallet
        if not permission_manager.check_permission(user_id, Permission.WRITE, wallet_id):
            raise HTTPException(status_code=403, detail="No write permission for this wallet")
    
    success = crypto_fs.write_wallet_data(wallet_id, wallet_data.dict())
    if not success:
        raise HTTPException(status_code=500, detail="Failed to store wallet data")
    
    # Grant the creator full permissions on the wallet
    permission_manager.grant_permission(user_id, Permission.READ, wallet_id)
    permission_manager.grant_permission(user_id, Permission.WRITE, wallet_id)
    permission_manager.grant_permission(user_id, Permission.DELETE, wallet_id)
    
    return {"message": "Wallet stored successfully", "wallet_id": wallet_id}


@app.get("/wallets/{wallet_id}")
async def read_wallet(
    wallet_id: str,
    user_id: str = Depends(verify_token)
):
    """Read encrypted wallet data."""
    # Check read permission for specific wallet
    if not permission_manager.check_permission(user_id, Permission.READ, wallet_id):
        raise HTTPException(status_code=403, detail="No read permission for this wallet")
    
    wallet_data = crypto_fs.read_wallet_data(wallet_id)
    if wallet_data is None:
        raise HTTPException(status_code=404, detail="Wallet not found")
    
    return wallet_data


@app.delete("/wallets/{wallet_id}")
async def delete_wallet(
    wallet_id: str,
    user_id: str = Depends(require_permission(Permission.DELETE))
):
    """Delete encrypted wallet data."""
    # Check delete permission for specific wallet
    if not permission_manager.check_permission(user_id, Permission.DELETE, wallet_id):
        raise HTTPException(status_code=403, detail="No delete permission for this wallet")
    
    success = crypto_fs.delete_wallet_data(wallet_id)
    if not success:
        raise HTTPException(status_code=500, detail="Failed to delete wallet data")
    
    return {"message": "Wallet deleted successfully", "wallet_id": wallet_id}


@app.post("/permissions/grant")
async def grant_permission(
    grant_data: PermissionGrant,
    admin_user: str = Depends(require_permission(Permission.ADMIN))
):
    """Grant permission to a user (admin only)."""
    try:
        permission = Permission(grant_data.permission.lower())
    except ValueError:
        raise HTTPException(status_code=400, detail="Invalid permission")
    
    success = permission_manager.grant_permission(
        grant_data.user_id, 
        permission, 
        grant_data.wallet_id
    )
    if not success:
        raise HTTPException(status_code=404, detail="User not found")
    
    return {
        "message": "Permission granted successfully",
        "user_id": grant_data.user_id,
        "permission": grant_data.permission,
        "wallet_id": grant_data.wallet_id
    }


@app.post("/permissions/revoke")
async def revoke_permission(
    grant_data: PermissionGrant,
    admin_user: str = Depends(require_permission(Permission.ADMIN))
):
    """Revoke permission from a user (admin only)."""
    try:
        permission = Permission(grant_data.permission.lower())
    except ValueError:
        raise HTTPException(status_code=400, detail="Invalid permission")
    
    success = permission_manager.revoke_permission(
        grant_data.user_id,
        permission,
        grant_data.wallet_id
    )
    if not success:
        raise HTTPException(status_code=404, detail="User not found")
    
    return {
        "message": "Permission revoked successfully",
        "user_id": grant_data.user_id,
        "permission": grant_data.permission,
        "wallet_id": grant_data.wallet_id
    }


@app.get("/permissions/users")
async def list_users(admin_user: str = Depends(require_permission(Permission.ADMIN))):
    """List all users and their permissions (admin only)."""
    return permission_manager.list_users()


@app.get("/permissions/{user_id}")
async def get_user_permissions(
    user_id: str,
    current_user: str = Depends(verify_token)
):
    """Get user permissions (users can see their own, admins can see any)."""
    if current_user != user_id and not permission_manager.check_permission(current_user, Permission.ADMIN):
        raise HTTPException(status_code=403, detail="Can only view your own permissions")
    
    if user_id not in permission_manager.users:
        raise HTTPException(status_code=404, detail="User not found")
    
    user = permission_manager.users[user_id]
    global_permissions = permission_manager.get_user_permissions(user_id)
    
    return {
        "user_id": user_id,
        "username": user.username,
        "role": user.role.value,
        "global_permissions": [p.value for p in global_permissions],
        "wallet_permissions": {
            wallet_id: [p.value for p in perms]
            for wallet_id, perms in user.wallet_permissions.items()
        }
    }


if __name__ == "__main__":
    # Create default admin user if none exists
    if not permission_manager.users:
        admin_id = permission_manager.create_user("admin", Role.SUPERUSER)
        print(f"Created default admin user with ID: {admin_id}")
    
    uvicorn.run(app, host="0.0.0.0", port=8000)