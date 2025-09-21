"""
Integration tests for the complete DID SSO Server API.
"""

import pytest
import tempfile
import shutil
from pathlib import Path
from fastapi.testclient import TestClient
import os

# Import our application
from main import app, crypto_fs, permission_manager
from permissions import Role, Permission


@pytest.fixture(scope="session")  
def temp_storage():
    """Create temporary storage for testing."""
    temp_dir = tempfile.mkdtemp()
    yield temp_dir
    shutil.rmtree(temp_dir)


@pytest.fixture
def client():
    """Create test client."""
    return TestClient(app)


@pytest.fixture
def admin_token(client):
    """Get admin token for testing."""
    # First create an admin user if none exists
    if not permission_manager.users:
        admin_id = permission_manager.create_user("admin", Role.SUPERUSER)
    else:
        admin_id = next(
            (uid for uid, user in permission_manager.users.items() 
             if user.role == Role.SUPERUSER), 
            None
        )
        if not admin_id:
            admin_id = permission_manager.create_user("admin", Role.SUPERUSER)
    
    response = client.post("/auth/login", params={"user_id": admin_id})
    return response.json()["access_token"]


@pytest.fixture
def regular_user_token(client, admin_token):
    """Create regular user and get token."""
    # Create regular user
    response = client.post(
        "/auth/create-user",
        json={"username": "testuser", "role": "user"},
        headers={"Authorization": f"Bearer {admin_token}"}
    )
    user_id = response.json()["user_id"]
    
    # Login as regular user
    response = client.post("/auth/login", params={"user_id": user_id})
    return response.json()["access_token"], user_id


def test_root_endpoint(client):
    """Test root endpoint."""
    response = client.get("/")
    assert response.status_code == 200
    data = response.json()
    assert "DID SSO Server" in data["message"]
    assert "features" in data


def test_create_user_admin_only(client, admin_token):
    """Test that only admins can create users."""
    # With admin token
    response = client.post(
        "/auth/create-user",
        json={"username": "newuser", "role": "user"},
        headers={"Authorization": f"Bearer {admin_token}"}
    )
    assert response.status_code == 200
    
    # Without token - should fail
    response = client.post(
        "/auth/create-user", 
        json={"username": "newuser2", "role": "user"}
    )
    assert response.status_code == 403


def test_wallet_operations(client, regular_user_token):
    """Test wallet create, read, delete operations."""
    token, user_id = regular_user_token
    headers = {"Authorization": f"Bearer {token}"}
    
    wallet_id = "test-wallet-123"
    wallet_data = {
        "wallet_id": wallet_id,
        "owner": "testuser",
        "did_document": {"id": "did:test:123"},
        "certificates": [],
        "metadata": {"created": "2024-01-01"}
    }
    
    # Create wallet
    response = client.post(
        f"/wallets/{wallet_id}",
        json=wallet_data,
        headers=headers
    )
    assert response.status_code == 200
    
    # Read wallet
    response = client.get(f"/wallets/{wallet_id}", headers=headers)
    assert response.status_code == 200
    assert response.json()["wallet_id"] == wallet_id
    
    # Delete wallet
    response = client.delete(f"/wallets/{wallet_id}", headers=headers)
    assert response.status_code == 200
    
    # Try to read deleted wallet
    response = client.get(f"/wallets/{wallet_id}", headers=headers)
    assert response.status_code == 404


def test_permission_enforcement(client, admin_token, regular_user_token):
    """Test that permissions are properly enforced."""
    admin_headers = {"Authorization": f"Bearer {admin_token}"}
    token, user_id = regular_user_token
    user_headers = {"Authorization": f"Bearer {token}"}
    
    # Create a wallet as another user (admin)
    admin_user_id = permission_manager.create_user("admin2", Role.ADMIN)
    admin_login = client.post("/auth/login", params={"user_id": admin_user_id})
    admin2_token = admin_login.json()["access_token"]
    admin2_headers = {"Authorization": f"Bearer {admin2_token}"}
    
    wallet_id = "restricted-wallet"
    wallet_data = {
        "wallet_id": wallet_id,
        "owner": "admin2",
        "did_document": {"id": "did:test:restricted"},
        "certificates": [],
        "metadata": {}
    }
    
    # Admin2 creates wallet
    response = client.post(f"/wallets/{wallet_id}", json=wallet_data, headers=admin2_headers)
    assert response.status_code == 200
    
    # Regular user tries to read - should fail (no permission)
    response = client.get(f"/wallets/{wallet_id}", headers=user_headers)
    assert response.status_code == 403
    
    # Grant read permission to regular user
    response = client.post(
        "/permissions/grant",
        json={"user_id": user_id, "permission": "read", "wallet_id": wallet_id},
        headers=admin_headers
    )
    assert response.status_code == 200
    
    # Now regular user can read
    response = client.get(f"/wallets/{wallet_id}", headers=user_headers)
    assert response.status_code == 200


def test_permission_management(client, admin_token):
    """Test permission management endpoints."""
    headers = {"Authorization": f"Bearer {admin_token}"}
    
    # Create test user
    response = client.post(
        "/auth/create-user",
        json={"username": "permtest", "role": "guest"},
        headers=headers
    )
    user_id = response.json()["user_id"]
    
    # Grant permission
    response = client.post(
        "/permissions/grant",
        json={"user_id": user_id, "permission": "write"},
        headers=headers
    )
    assert response.status_code == 200
    
    # List users
    response = client.get("/permissions/users", headers=headers)
    assert response.status_code == 200
    users = response.json()
    assert len(users) >= 1
    
    # Get user permissions
    response = client.get(f"/permissions/{user_id}", headers=headers)
    assert response.status_code == 200
    perms = response.json()
    assert "write" in perms["global_permissions"]
    
    # Revoke permission
    response = client.post(
        "/permissions/revoke",
        json={"user_id": user_id, "permission": "write"},
        headers=headers
    )
    assert response.status_code == 200


def test_authentication_required(client):
    """Test that protected endpoints require authentication."""
    endpoints = [
        ("GET", "/auth/me"),
        ("POST", "/wallets/test"),
        ("GET", "/wallets/test"),
        ("DELETE", "/wallets/test"),
        ("POST", "/permissions/grant"),
        ("POST", "/permissions/revoke"),
        ("GET", "/permissions/users"),
        ("GET", "/permissions/testuser"),
    ]
    
    for method, endpoint in endpoints:
        if method == "GET":
            response = client.get(endpoint)
        elif method == "POST":
            response = client.post(endpoint, json={})
        elif method == "DELETE":
            response = client.delete(endpoint)
        
        assert response.status_code == 403


def test_invalid_permissions(client, admin_token):
    """Test handling of invalid permissions and roles."""
    headers = {"Authorization": f"Bearer {admin_token}"}
    
    # Try to create user with invalid role
    response = client.post(
        "/auth/create-user",
        json={"username": "test", "role": "invalid_role"},
        headers=headers
    )
    assert response.status_code == 400
    
    # Create valid user for permission tests
    response = client.post(
        "/auth/create-user",
        json={"username": "test", "role": "user"},
        headers=headers
    )
    user_id = response.json()["user_id"]
    
    # Try to grant invalid permission
    response = client.post(
        "/permissions/grant",
        json={"user_id": user_id, "permission": "invalid_permission"},
        headers=headers
    )
    assert response.status_code == 400