"""
Tests for the permission management system.
"""

import pytest
import tempfile
import os
from pathlib import Path

from permissions import PermissionManager, Permission, Role


@pytest.fixture
def temp_permissions_file():
    """Create temporary permissions file for tests."""
    temp_file = tempfile.NamedTemporaryFile(suffix='.json', delete=False)
    temp_file.close()
    yield temp_file.name
    if os.path.exists(temp_file.name):
        os.unlink(temp_file.name)


@pytest.fixture
def perm_manager(temp_permissions_file):
    """Create PermissionManager instance for testing."""
    return PermissionManager(temp_permissions_file)


def test_create_user(perm_manager):
    """Test creating a new user."""
    user_id = perm_manager.create_user("testuser", Role.USER)
    
    assert user_id in perm_manager.users
    user = perm_manager.users[user_id]
    assert user.username == "testuser"
    assert user.role == Role.USER
    assert user.custom_permissions == set()
    assert user.wallet_permissions == {}


def test_role_based_permissions(perm_manager):
    """Test that roles provide correct default permissions."""
    # Create users with different roles
    guest_id = perm_manager.create_user("guest", Role.GUEST)
    user_id = perm_manager.create_user("user", Role.USER)
    admin_id = perm_manager.create_user("admin", Role.ADMIN)
    super_id = perm_manager.create_user("super", Role.SUPERUSER)
    
    # Check role-based permissions
    assert perm_manager.get_user_permissions(guest_id) == set()
    assert perm_manager.get_user_permissions(user_id) == {Permission.READ}
    assert perm_manager.get_user_permissions(admin_id) == {Permission.READ, Permission.WRITE}
    assert perm_manager.get_user_permissions(super_id) == {Permission.READ, Permission.WRITE, Permission.DELETE, Permission.ADMIN}


def test_grant_custom_permission(perm_manager):
    """Test granting custom permissions to users."""
    user_id = perm_manager.create_user("testuser", Role.GUEST)
    
    # Grant write permission
    assert perm_manager.grant_permission(user_id, Permission.WRITE)
    
    permissions = perm_manager.get_user_permissions(user_id)
    assert Permission.WRITE in permissions


def test_wallet_specific_permissions(perm_manager):
    """Test wallet-specific permission management."""
    user_id = perm_manager.create_user("testuser", Role.GUEST)
    wallet_id = "test-wallet-123"
    
    # Grant wallet-specific permission
    assert perm_manager.grant_permission(user_id, Permission.READ, wallet_id)
    
    # Check global permissions (should be empty)
    global_perms = perm_manager.get_user_permissions(user_id)
    assert global_perms == set()
    
    # Check wallet-specific permissions
    wallet_perms = perm_manager.get_user_permissions(user_id, wallet_id)
    assert Permission.READ in wallet_perms


def test_check_permission(perm_manager):
    """Test permission checking."""
    user_id = perm_manager.create_user("testuser", Role.USER)
    wallet_id = "test-wallet-456"
    
    # Should have read permission from role
    assert perm_manager.check_permission(user_id, Permission.READ)
    
    # Should not have write permission
    assert not perm_manager.check_permission(user_id, Permission.WRITE)
    
    # Grant wallet-specific write permission
    perm_manager.grant_permission(user_id, Permission.WRITE, wallet_id)
    
    # Should have write permission for that wallet
    assert perm_manager.check_permission(user_id, Permission.WRITE, wallet_id)
    
    # Should not have write permission globally
    assert not perm_manager.check_permission(user_id, Permission.WRITE)


def test_revoke_permission(perm_manager):
    """Test revoking permissions."""
    user_id = perm_manager.create_user("testuser", Role.ADMIN)
    wallet_id = "test-wallet-789"
    
    # Grant additional permission
    perm_manager.grant_permission(user_id, Permission.DELETE, wallet_id)
    assert perm_manager.check_permission(user_id, Permission.DELETE, wallet_id)
    
    # Revoke the permission
    assert perm_manager.revoke_permission(user_id, Permission.DELETE, wallet_id)
    assert not perm_manager.check_permission(user_id, Permission.DELETE, wallet_id)


def test_set_user_role(perm_manager):
    """Test changing user roles."""
    user_id = perm_manager.create_user("testuser", Role.GUEST)
    
    # Initially no permissions
    assert perm_manager.get_user_permissions(user_id) == set()
    
    # Change to admin role
    assert perm_manager.set_user_role(user_id, Role.ADMIN)
    
    # Should now have admin permissions
    permissions = perm_manager.get_user_permissions(user_id)
    assert Permission.READ in permissions
    assert Permission.WRITE in permissions


def test_persistence(temp_permissions_file):
    """Test that permissions are saved and loaded correctly."""
    # Create manager and add user
    manager1 = PermissionManager(temp_permissions_file)
    user_id = manager1.create_user("testuser", Role.USER)
    manager1.grant_permission(user_id, Permission.WRITE, "wallet123")
    
    # Create new manager instance (should load from file)
    manager2 = PermissionManager(temp_permissions_file)
    
    # Verify user was loaded
    assert user_id in manager2.users
    user = manager2.users[user_id]
    assert user.username == "testuser"
    assert user.role == Role.USER
    assert "wallet123" in user.wallet_permissions
    assert Permission.WRITE in user.wallet_permissions["wallet123"]


def test_list_users(perm_manager):
    """Test listing users."""
    user1_id = perm_manager.create_user("user1", Role.USER)
    user2_id = perm_manager.create_user("user2", Role.ADMIN)
    
    users = perm_manager.list_users()
    assert len(users) == 2
    
    usernames = {user['username'] for user in users}
    assert "user1" in usernames
    assert "user2" in usernames


def test_delete_user(perm_manager):
    """Test deleting users."""
    user_id = perm_manager.create_user("testuser", Role.USER)
    
    # Verify user exists
    assert user_id in perm_manager.users
    
    # Delete user
    assert perm_manager.delete_user(user_id)
    
    # Verify user is gone
    assert user_id not in perm_manager.users
    
    # Try to delete non-existent user
    assert not perm_manager.delete_user("nonexistent")


def test_invalid_user_operations(perm_manager):
    """Test operations on non-existent users."""
    fake_user_id = "nonexistent-user"
    
    # Should return False/empty for non-existent users
    assert perm_manager.get_user_permissions(fake_user_id) == set()
    assert not perm_manager.check_permission(fake_user_id, Permission.READ)
    assert not perm_manager.grant_permission(fake_user_id, Permission.READ)
    assert not perm_manager.revoke_permission(fake_user_id, Permission.READ)
    assert not perm_manager.set_user_role(fake_user_id, Role.ADMIN)