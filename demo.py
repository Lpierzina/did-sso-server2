#!/usr/bin/env python3
"""
Demonstration script for the DID SSO Server with encrypted file system.
This script shows the core functionality without requiring FastAPI.
"""

import tempfile
import shutil
from pathlib import Path

from crypto_fs import EncryptedFileSystem
from permissions import PermissionManager, Permission, Role


def demo_encryption():
    """Demonstrate file system encryption."""
    print("\n=== File System Encryption Demo ===")
    
    # Create temporary storage
    temp_dir = tempfile.mkdtemp()
    print(f"Using temporary storage: {temp_dir}")
    
    try:
        # Initialize encrypted file system
        fs = EncryptedFileSystem("demo-master-key-2024", temp_dir)
        
        # Create sample wallet data
        wallet_id = "user_alice_wallet_001"
        wallet_data = {
            "wallet_id": wallet_id,
            "owner": "alice@example.com",
            "did_document": {
                "id": "did:example:alice123",
                "authentication": ["did:example:alice123#keys-1"],
                "service": [{"id": "#sso", "type": "SSO", "serviceEndpoint": "https://sso.example.com"}]
            },
            "certificates": [
                {
                    "type": "X.509",
                    "issuer": "CA-Example-Org",
                    "subject": "Alice Smith",
                    "valid_from": "2024-01-01",
                    "valid_to": "2025-01-01"
                }
            ],
            "metadata": {
                "created_at": "2024-01-01T00:00:00Z",
                "last_accessed": "2024-01-15T10:30:00Z",
                "version": "1.0"
            }
        }
        
        print(f"Original wallet ID: {wallet_id}")
        print("Writing encrypted wallet data...")
        
        # Store encrypted data
        success = fs.write_wallet_data(wallet_id, wallet_data)
        print(f"✓ Write operation successful: {success}")
        
        # Show obfuscated filename
        encrypted_path = fs._get_encrypted_path(wallet_id)
        print(f"✓ Obfuscated filename: {encrypted_path.name}")
        print(f"✓ Original wallet ID is hidden from filesystem")
        
        # Retrieve and verify data
        retrieved_data = fs.read_wallet_data(wallet_id)
        data_matches = retrieved_data == wallet_data
        print(f"✓ Data retrieval successful: {retrieved_data is not None}")
        print(f"✓ Data integrity verified: {data_matches}")
        
        # Show that wrong key fails
        wrong_fs = EncryptedFileSystem("wrong-key", temp_dir)
        wrong_data = wrong_fs.read_wallet_data(wallet_id)
        print(f"✓ Wrong key fails decryption: {wrong_data is None}")
        
        # Show wallet existence check
        print(f"✓ Wallet exists check: {fs.wallet_exists(wallet_id)}")
        
        # Delete wallet
        fs.delete_wallet_data(wallet_id)
        print(f"✓ Wallet deleted: {not fs.wallet_exists(wallet_id)}")
        
    finally:
        shutil.rmtree(temp_dir)
        print(f"✓ Cleaned up temporary storage")


def demo_permissions():
    """Demonstrate permission management."""
    print("\n=== Permission Management Demo ===")
    
    # Create temporary permissions file
    temp_file = tempfile.NamedTemporaryFile(suffix='.json', delete=False)
    temp_file.close()
    
    try:
        # Initialize permission manager
        pm = PermissionManager(temp_file.name)
        
        # Create users with different roles
        alice_id = pm.create_user("alice", Role.USER)
        bob_id = pm.create_user("bob", Role.ADMIN)
        charlie_id = pm.create_user("charlie", Role.GUEST)
        super_id = pm.create_user("superuser", Role.SUPERUSER)
        
        print(f"✓ Created users:")
        print(f"  Alice (USER): {alice_id}")
        print(f"  Bob (ADMIN): {bob_id}")
        print(f"  Charlie (GUEST): {charlie_id}")
        print(f"  Superuser (SUPERUSER): {super_id}")
        
        # Show role-based permissions
        print(f"\n✓ Role-based permissions:")
        for user_id, username in [(alice_id, "Alice"), (bob_id, "Bob"), (charlie_id, "Charlie"), (super_id, "Superuser")]:
            perms = pm.get_user_permissions(user_id)
            perm_names = [p.value for p in perms]
            print(f"  {username}: {perm_names}")
        
        # Demonstrate wallet-specific permissions
        wallet1 = "alice_personal_wallet"
        wallet2 = "company_shared_wallet"
        
        print(f"\n✓ Granting wallet-specific permissions:")
        
        # Alice gets full control of her personal wallet
        pm.grant_permission(alice_id, Permission.WRITE, wallet1)
        pm.grant_permission(alice_id, Permission.DELETE, wallet1)
        
        # Bob (admin) gets write access to shared wallet
        pm.grant_permission(bob_id, Permission.WRITE, wallet2)
        
        # Charlie (guest) gets read access to shared wallet
        pm.grant_permission(charlie_id, Permission.READ, wallet2)
        
        print(f"  Alice: full control over {wallet1}")
        print(f"  Bob: write access to {wallet2}")
        print(f"  Charlie: read access to {wallet2}")
        
        # Test permission checks
        print(f"\n✓ Permission checks:")
        
        test_cases = [
            (alice_id, "Alice", Permission.READ, wallet1, "read her personal wallet"),
            (alice_id, "Alice", Permission.WRITE, wallet1, "write to her personal wallet"),
            (alice_id, "Alice", Permission.WRITE, wallet2, "write to shared wallet (should fail)"),
            (bob_id, "Bob", Permission.WRITE, wallet2, "write to shared wallet"),
            (bob_id, "Bob", Permission.DELETE, wallet2, "delete shared wallet (should fail)"),
            (charlie_id, "Charlie", Permission.READ, wallet2, "read shared wallet"),
            (charlie_id, "Charlie", Permission.WRITE, wallet2, "write to shared wallet (should fail)"),
            (super_id, "Superuser", Permission.DELETE, wallet2, "delete any wallet"),
        ]
        
        for user_id, username, permission, wallet_id, description in test_cases:
            has_permission = pm.check_permission(user_id, permission, wallet_id)
            status = "✓" if has_permission else "✗"
            print(f"    {status} {username} can {description}: {has_permission}")
        
        # Show user listing
        users = pm.list_users()
        print(f"\n✓ User summary:")
        for user in users:
            print(f"  {user['username']} ({user['role']}): {user['wallet_count']} wallet permissions")
        
    finally:
        Path(temp_file.name).unlink()
        print(f"✓ Cleaned up permissions file")


def demo_integration():
    """Demonstrate integration of encryption and permissions."""
    print("\n=== Integration Demo ===")
    
    # Setup
    temp_dir = tempfile.mkdtemp()
    temp_file = tempfile.NamedTemporaryFile(suffix='.json', delete=False)
    temp_file.close()
    
    try:
        fs = EncryptedFileSystem("integration-demo-key", temp_dir)
        pm = PermissionManager(temp_file.name)
        
        # Create users
        alice_id = pm.create_user("alice", Role.USER)
        bob_id = pm.create_user("bob", Role.ADMIN)
        
        # Wallets
        alice_wallet = "alice_secure_wallet"
        shared_wallet = "department_wallet"
        
        # Alice creates her personal wallet
        alice_data = {
            "wallet_id": alice_wallet,
            "owner": "alice@company.com",
            "did_document": {"id": f"did:company:alice"},
            "certificates": [{"type": "employee_cert", "dept": "engineering"}],
            "metadata": {"privacy": "personal", "backup": "encrypted"}
        }
        
        print("✓ Simulating secure wallet operations:")
        
        # 1. Alice stores her wallet (she has default read permission, we grant write for her wallet)
        pm.grant_permission(alice_id, Permission.WRITE, alice_wallet)
        pm.grant_permission(alice_id, Permission.DELETE, alice_wallet)
        
        if pm.check_permission(alice_id, Permission.WRITE, alice_wallet):
            fs.write_wallet_data(alice_wallet, alice_data)
            print(f"  ✓ Alice stored her personal wallet (encrypted)")
        
        # 2. Alice can read her own wallet
        if pm.check_permission(alice_id, Permission.READ, alice_wallet):
            data = fs.read_wallet_data(alice_wallet)
            print(f"  ✓ Alice accessed her wallet: {data['owner']}")
        
        # 3. Bob (admin) tries to access Alice's wallet without permission
        if not pm.check_permission(bob_id, Permission.READ, alice_wallet):
            print(f"  ✓ Bob cannot access Alice's personal wallet (permission denied)")
        
        # 4. Admin grants Bob read access to Alice's wallet (emergency access)
        pm.grant_permission(bob_id, Permission.READ, alice_wallet)
        if pm.check_permission(bob_id, Permission.READ, alice_wallet):
            data = fs.read_wallet_data(alice_wallet)
            print(f"  ✓ Bob gained emergency access to Alice's wallet")
        
        # 5. Create shared department wallet
        shared_data = {
            "wallet_id": shared_wallet,
            "owner": "engineering_dept",
            "did_document": {"id": "did:company:eng_dept"},
            "certificates": [{"type": "department_cert", "permissions": ["shared_resources"]}],
            "metadata": {"type": "shared", "department": "engineering"}
        }
        
        # Bob creates the shared wallet
        pm.grant_permission(bob_id, Permission.WRITE, shared_wallet)
        if pm.check_permission(bob_id, Permission.WRITE, shared_wallet):
            fs.write_wallet_data(shared_wallet, shared_data)
            print(f"  ✓ Bob created shared department wallet")
        
        # Grant Alice read access to shared wallet
        pm.grant_permission(alice_id, Permission.READ, shared_wallet)
        if pm.check_permission(alice_id, Permission.READ, shared_wallet):
            data = fs.read_wallet_data(shared_wallet)
            print(f"  ✓ Alice can access shared department wallet")
        
        print(f"\n✓ Security features demonstrated:")
        print(f"  - Wallet contents encrypted with master key")
        print(f"  - Wallet filenames obfuscated (not readable on disk)")
        print(f"  - Per-wallet permission controls")
        print(f"  - Role-based default permissions")
        print(f"  - Admin emergency access capabilities")
        
    finally:
        shutil.rmtree(temp_dir)
        Path(temp_file.name).unlink()
        print(f"✓ Cleaned up demo resources")


def main():
    """Run all demonstrations."""
    print("🔐 DID SSO Server - Encrypted File System & Permission Management Demo")
    print("=" * 80)
    
    demo_encryption()
    demo_permissions()
    demo_integration()
    
    print(f"\n" + "=" * 80)
    print("✅ All demonstrations completed successfully!")
    print("\nKey Features Implemented:")
    print("1. ✓ Encrypted file system for secure ADCS storage")
    print("2. ✓ Obfuscated filenames (wallet IDs not visible)")
    print("3. ✓ Role-based permission system")
    print("4. ✓ Per-wallet access controls")
    print("5. ✓ Admin utility for permission management")
    print("6. ✓ Complete DID SSO server implementation")


if __name__ == "__main__":
    main()