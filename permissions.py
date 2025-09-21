"""
Permission management system for DID SSO server.
Provides role-based access control for wallet operations.
"""

import json
import hashlib
import time
from typing import Dict, Set, Optional, List
from enum import Enum
from pathlib import Path
from dataclasses import dataclass


class Permission(Enum):
    """Available permissions for wallet access."""
    READ = "read"
    WRITE = "write"
    DELETE = "delete"
    ADMIN = "admin"


class Role(Enum):
    """Predefined roles with permission sets."""
    GUEST = "guest"
    USER = "user"  
    ADMIN = "admin"
    SUPERUSER = "superuser"


@dataclass
class User:
    """User representation with permissions."""
    user_id: str
    username: str
    role: Role
    custom_permissions: Set[Permission]
    wallet_permissions: Dict[str, Set[Permission]]  # wallet_id -> permissions
    created_at: float
    last_access: float


class PermissionManager:
    """Manages user permissions and access control."""
    
    # Default role permissions
    ROLE_PERMISSIONS = {
        Role.GUEST: set(),
        Role.USER: {Permission.READ},
        Role.ADMIN: {Permission.READ, Permission.WRITE},
        Role.SUPERUSER: {Permission.READ, Permission.WRITE, Permission.DELETE, Permission.ADMIN}
    }
    
    def __init__(self, permissions_file: str = "permissions.json"):
        """
        Initialize permission manager.
        
        Args:
            permissions_file: Path to permissions storage file
        """
        self.permissions_file = Path(permissions_file)
        self.users: Dict[str, User] = {}
        self._load_permissions()
    
    def _load_permissions(self) -> None:
        """Load permissions from file."""
        if self.permissions_file.exists():
            try:
                with open(self.permissions_file, 'r') as f:
                    data = json.load(f)
                    
                for user_data in data.get('users', []):
                    user = User(
                        user_id=user_data['user_id'],
                        username=user_data['username'],
                        role=Role(user_data['role']),
                        custom_permissions={Permission(p) for p in user_data.get('custom_permissions', [])},
                        wallet_permissions={
                            wallet_id: {Permission(p) for p in perms}
                            for wallet_id, perms in user_data.get('wallet_permissions', {}).items()
                        },
                        created_at=user_data.get('created_at', time.time()),
                        last_access=user_data.get('last_access', time.time())
                    )
                    self.users[user.user_id] = user
            except Exception as e:
                print(f"Error loading permissions: {e}")
    
    def _save_permissions(self) -> None:
        """Save permissions to file."""
        try:
            data = {
                'users': [
                    {
                        'user_id': user.user_id,
                        'username': user.username,
                        'role': user.role.value,
                        'custom_permissions': [p.value for p in user.custom_permissions],
                        'wallet_permissions': {
                            wallet_id: [p.value for p in perms]
                            for wallet_id, perms in user.wallet_permissions.items()
                        },
                        'created_at': user.created_at,
                        'last_access': user.last_access
                    }
                    for user in self.users.values()
                ]
            }
            
            with open(self.permissions_file, 'w') as f:
                json.dump(data, f, indent=2)
        except Exception as e:
            print(f"Error saving permissions: {e}")
    
    def create_user(self, username: str, role: Role = Role.USER) -> str:
        """
        Create a new user with specified role.
        
        Args:
            username: Username for the new user
            role: Role to assign to the user
            
        Returns:
            Generated user ID
        """
        user_id = hashlib.sha256(f"{username}_{time.time()}".encode()).hexdigest()[:16]
        
        user = User(
            user_id=user_id,
            username=username,
            role=role,
            custom_permissions=set(),
            wallet_permissions={},
            created_at=time.time(),
            last_access=time.time()
        )
        
        self.users[user_id] = user
        self._save_permissions()
        return user_id
    
    def get_user_permissions(self, user_id: str, wallet_id: Optional[str] = None) -> Set[Permission]:
        """
        Get effective permissions for a user.
        
        Args:
            user_id: User identifier
            wallet_id: Optional wallet ID for wallet-specific permissions
            
        Returns:
            Set of effective permissions
        """
        if user_id not in self.users:
            return set()
        
        user = self.users[user_id]
        
        # Start with role-based permissions
        permissions = self.ROLE_PERMISSIONS.get(user.role, set()).copy()
        
        # Add custom permissions
        permissions.update(user.custom_permissions)
        
        # Add wallet-specific permissions if requested
        if wallet_id and wallet_id in user.wallet_permissions:
            permissions.update(user.wallet_permissions[wallet_id])
        
        return permissions
    
    def check_permission(self, user_id: str, permission: Permission, wallet_id: Optional[str] = None) -> bool:
        """
        Check if user has specific permission.
        
        Args:
            user_id: User identifier
            permission: Permission to check
            wallet_id: Optional wallet ID for wallet-specific permissions
            
        Returns:
            True if user has permission, False otherwise
        """
        user_permissions = self.get_user_permissions(user_id, wallet_id)
        return permission in user_permissions
    
    def grant_permission(self, user_id: str, permission: Permission, wallet_id: Optional[str] = None) -> bool:
        """
        Grant permission to user.
        
        Args:
            user_id: User identifier
            permission: Permission to grant
            wallet_id: Optional wallet ID for wallet-specific permissions
            
        Returns:
            True if successful, False otherwise
        """
        if user_id not in self.users:
            return False
        
        user = self.users[user_id]
        
        if wallet_id:
            if wallet_id not in user.wallet_permissions:
                user.wallet_permissions[wallet_id] = set()
            user.wallet_permissions[wallet_id].add(permission)
        else:
            user.custom_permissions.add(permission)
        
        self._save_permissions()
        return True
    
    def revoke_permission(self, user_id: str, permission: Permission, wallet_id: Optional[str] = None) -> bool:
        """
        Revoke permission from user.
        
        Args:
            user_id: User identifier
            permission: Permission to revoke
            wallet_id: Optional wallet ID for wallet-specific permissions
            
        Returns:
            True if successful, False otherwise
        """
        if user_id not in self.users:
            return False
        
        user = self.users[user_id]
        
        if wallet_id and wallet_id in user.wallet_permissions:
            user.wallet_permissions[wallet_id].discard(permission)
            if not user.wallet_permissions[wallet_id]:
                del user.wallet_permissions[wallet_id]
        else:
            user.custom_permissions.discard(permission)
        
        self._save_permissions()
        return True
    
    def set_user_role(self, user_id: str, role: Role) -> bool:
        """
        Set user role.
        
        Args:
            user_id: User identifier
            role: New role to assign
            
        Returns:
            True if successful, False otherwise
        """
        if user_id not in self.users:
            return False
        
        self.users[user_id].role = role
        self._save_permissions()
        return True
    
    def list_users(self) -> List[Dict]:
        """
        List all users with their permissions.
        
        Returns:
            List of user information dictionaries
        """
        return [
            {
                'user_id': user.user_id,
                'username': user.username,
                'role': user.role.value,
                'custom_permissions': [p.value for p in user.custom_permissions],
                'wallet_count': len(user.wallet_permissions),
                'created_at': user.created_at,
                'last_access': user.last_access
            }
            for user in self.users.values()
        ]
    
    def update_last_access(self, user_id: str) -> None:
        """Update user's last access time."""
        if user_id in self.users:
            self.users[user_id].last_access = time.time()
            self._save_permissions()
    
    def delete_user(self, user_id: str) -> bool:
        """
        Delete a user.
        
        Args:
            user_id: User identifier
            
        Returns:
            True if successful, False otherwise
        """
        if user_id in self.users:
            del self.users[user_id]
            self._save_permissions()
            return True
        return False