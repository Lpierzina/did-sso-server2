#!/usr/bin/env python3
"""
DID SSO Server Permission Management CLI Utility

This utility provides command-line interface for managing user permissions
in the DID SSO Server with encrypted file system.
"""

import click
import requests
import json
from typing import Optional
import sys


class SSO_Client:
    """Client for interacting with DID SSO Server API."""
    
    def __init__(self, base_url: str = "http://localhost:8000", token: Optional[str] = None):
        self.base_url = base_url.rstrip('/')
        self.token = token
        self.headers = {}
        if token:
            self.headers['Authorization'] = f'Bearer {token}'
    
    def login(self, user_id: str) -> str:
        """Login and get access token."""
        response = requests.post(
            f"{self.base_url}/auth/login",
            params={"user_id": user_id}
        )
        if response.status_code == 200:
            return response.json()["access_token"]
        else:
            raise Exception(f"Login failed: {response.text}")
    
    def create_user(self, username: str, role: str = "user") -> dict:
        """Create a new user."""
        response = requests.post(
            f"{self.base_url}/auth/create-user",
            headers=self.headers,
            json={"username": username, "role": role}
        )
        if response.status_code == 200:
            return response.json()
        else:
            raise Exception(f"User creation failed: {response.text}")
    
    def grant_permission(self, user_id: str, permission: str, wallet_id: Optional[str] = None) -> dict:
        """Grant permission to user."""
        data = {"user_id": user_id, "permission": permission}
        if wallet_id:
            data["wallet_id"] = wallet_id
        
        response = requests.post(
            f"{self.base_url}/permissions/grant",
            headers=self.headers,
            json=data
        )
        if response.status_code == 200:
            return response.json()
        else:
            raise Exception(f"Permission grant failed: {response.text}")
    
    def revoke_permission(self, user_id: str, permission: str, wallet_id: Optional[str] = None) -> dict:
        """Revoke permission from user."""
        data = {"user_id": user_id, "permission": permission}
        if wallet_id:
            data["wallet_id"] = wallet_id
        
        response = requests.post(
            f"{self.base_url}/permissions/revoke",
            headers=self.headers,
            json=data
        )
        if response.status_code == 200:
            return response.json()
        else:
            raise Exception(f"Permission revoke failed: {response.text}")
    
    def list_users(self) -> list:
        """List all users."""
        response = requests.get(
            f"{self.base_url}/permissions/users",
            headers=self.headers
        )
        if response.status_code == 200:
            return response.json()
        else:
            raise Exception(f"Failed to list users: {response.text}")
    
    def get_user_permissions(self, user_id: str) -> dict:
        """Get user permissions."""
        response = requests.get(
            f"{self.base_url}/permissions/{user_id}",
            headers=self.headers
        )
        if response.status_code == 200:
            return response.json()
        else:
            raise Exception(f"Failed to get user permissions: {response.text}")


@click.group()
@click.option('--url', default='http://localhost:8000', help='SSO Server URL')
@click.option('--token', help='Authentication token')
@click.pass_context
def cli(ctx, url, token):
    """DID SSO Server Permission Management CLI"""
    ctx.ensure_object(dict)
    ctx.obj['client'] = SSO_Client(url, token)


@cli.command()
@click.argument('user_id')
@click.pass_context
def login(ctx, user_id):
    """Login and get access token"""
    try:
        client = ctx.obj['client']
        token = client.login(user_id)
        click.echo(f"Login successful!")
        click.echo(f"Access token: {token}")
        click.echo(f"Use this token with --token option for subsequent commands")
    except Exception as e:
        click.echo(f"Error: {e}", err=True)
        sys.exit(1)


@cli.command()
@click.argument('username')
@click.option('--role', default='user', help='User role (guest, user, admin, superuser)')
@click.pass_context
def create_user(ctx, username, role):
    """Create a new user"""
    try:
        client = ctx.obj['client']
        if not client.token:
            click.echo("Error: Authentication token required. Use login command first.", err=True)
            sys.exit(1)
        
        result = client.create_user(username, role)
        click.echo(f"User created successfully!")
        click.echo(f"User ID: {result['user_id']}")
        click.echo(f"Username: {result['username']}")
        click.echo(f"Role: {result['role']}")
    except Exception as e:
        click.echo(f"Error: {e}", err=True)
        sys.exit(1)


@cli.command()
@click.argument('user_id')
@click.argument('permission')
@click.option('--wallet-id', help='Wallet ID for wallet-specific permission')
@click.pass_context
def grant(ctx, user_id, permission, wallet_id):
    """Grant permission to user"""
    try:
        client = ctx.obj['client']
        if not client.token:
            click.echo("Error: Authentication token required. Use login command first.", err=True)
            sys.exit(1)
        
        result = client.grant_permission(user_id, permission, wallet_id)
        click.echo(f"Permission granted successfully!")
        click.echo(f"User: {result['user_id']}")
        click.echo(f"Permission: {result['permission']}")
        if wallet_id:
            click.echo(f"Wallet: {result['wallet_id']}")
    except Exception as e:
        click.echo(f"Error: {e}", err=True)
        sys.exit(1)


@cli.command()
@click.argument('user_id')
@click.argument('permission')
@click.option('--wallet-id', help='Wallet ID for wallet-specific permission')
@click.pass_context
def revoke(ctx, user_id, permission, wallet_id):
    """Revoke permission from user"""
    try:
        client = ctx.obj['client']
        if not client.token:
            click.echo("Error: Authentication token required. Use login command first.", err=True)
            sys.exit(1)
        
        result = client.revoke_permission(user_id, permission, wallet_id)
        click.echo(f"Permission revoked successfully!")
        click.echo(f"User: {result['user_id']}")
        click.echo(f"Permission: {result['permission']}")
        if wallet_id:
            click.echo(f"Wallet: {result['wallet_id']}")
    except Exception as e:
        click.echo(f"Error: {e}", err=True)
        sys.exit(1)


@cli.command()
@click.pass_context
def list_users(ctx):
    """List all users and their permissions"""
    try:
        client = ctx.obj['client']
        if not client.token:
            click.echo("Error: Authentication token required. Use login command first.", err=True)
            sys.exit(1)
        
        users = client.list_users()
        
        if not users:
            click.echo("No users found.")
            return
        
        click.echo(f"{'User ID':<20} {'Username':<15} {'Role':<10} {'Permissions':<15} {'Wallets':<10}")
        click.echo("-" * 75)
        
        for user in users:
            click.echo(
                f"{user['user_id']:<20} "
                f"{user['username']:<15} "
                f"{user['role']:<10} "
                f"{len(user['custom_permissions']):<15} "
                f"{user['wallet_count']:<10}"
            )
    except Exception as e:
        click.echo(f"Error: {e}", err=True)
        sys.exit(1)


@cli.command()
@click.argument('user_id')
@click.pass_context
def show_permissions(ctx, user_id):
    """Show detailed permissions for a user"""
    try:
        client = ctx.obj['client']
        if not client.token:
            click.echo("Error: Authentication token required. Use login command first.", err=True)
            sys.exit(1)
        
        permissions = client.get_user_permissions(user_id)
        
        click.echo(f"User: {permissions['username']} ({permissions['user_id']})")
        click.echo(f"Role: {permissions['role']}")
        click.echo(f"Global Permissions: {', '.join(permissions['global_permissions'])}")
        
        if permissions['wallet_permissions']:
            click.echo("\nWallet-specific permissions:")
            for wallet_id, perms in permissions['wallet_permissions'].items():
                click.echo(f"  {wallet_id}: {', '.join(perms)}")
        else:
            click.echo("\nNo wallet-specific permissions.")
            
    except Exception as e:
        click.echo(f"Error: {e}", err=True)
        sys.exit(1)


@cli.command()
def help_permissions():
    """Show available permissions and roles"""
    click.echo("Available Permissions:")
    click.echo("  read    - Read wallet data")
    click.echo("  write   - Create/modify wallet data")
    click.echo("  delete  - Delete wallet data")
    click.echo("  admin   - Administrative operations")
    click.echo()
    click.echo("Available Roles:")
    click.echo("  guest     - No default permissions")
    click.echo("  user      - Read permission")
    click.echo("  admin     - Read, Write permissions")
    click.echo("  superuser - All permissions")
    click.echo()
    click.echo("Examples:")
    click.echo("  # Login as admin")
    click.echo("  sso-admin login <admin_user_id>")
    click.echo()
    click.echo("  # Create a new user")
    click.echo("  sso-admin --token <token> create-user johndoe --role user")
    click.echo()
    click.echo("  # Grant wallet-specific write permission")
    click.echo("  sso-admin --token <token> grant <user_id> write --wallet-id wallet123")
    click.echo()
    click.echo("  # List all users")
    click.echo("  sso-admin --token <token> list-users")


if __name__ == '__main__':
    cli()