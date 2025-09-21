"""
Cryptographic file system for secure ADCS storage.
Provides encryption/decryption capabilities for wallet files.
"""

import os
import base64
from pathlib import Path
from typing import Optional, Dict, Any
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import json
import hashlib


class EncryptedFileSystem:
    """Handles encrypted file operations for secure ADCS storage."""
    
    def __init__(self, master_key: str, storage_path: str = "encrypted_storage"):
        """
        Initialize the encrypted file system.
        
        Args:
            master_key: Master password for encryption
            storage_path: Base directory for encrypted storage
        """
        self.storage_path = Path(storage_path)
        self.storage_path.mkdir(exist_ok=True)
        
        # Generate encryption key from master password
        self._encryption_key = self._derive_key(master_key)
        self._fernet = Fernet(self._encryption_key)
        
    def _derive_key(self, password: str) -> bytes:
        """Derive encryption key from password using PBKDF2."""
        # Use a fixed salt for consistency (in production, store salt securely)
        salt = b"did_sso_server_salt_2024"
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
        )
        key = base64.urlsafe_b64encode(kdf.derive(password.encode()))
        return key
    
    def _get_encrypted_path(self, wallet_id: str) -> Path:
        """Convert wallet ID to encrypted filename."""
        # Hash the wallet ID to obfuscate directory structure
        hashed_id = hashlib.sha256(wallet_id.encode()).hexdigest()[:16]
        return self.storage_path / f"{hashed_id}.enc"
    
    def write_wallet_data(self, wallet_id: str, data: Dict[str, Any]) -> bool:
        """
        Write encrypted wallet data to filesystem.
        
        Args:
            wallet_id: Unique identifier for the wallet
            data: Wallet data to encrypt and store
            
        Returns:
            True if successful, False otherwise
        """
        try:
            # Serialize data to JSON
            json_data = json.dumps(data, indent=2)
            
            # Encrypt the data
            encrypted_data = self._fernet.encrypt(json_data.encode())
            
            # Write to encrypted file
            encrypted_path = self._get_encrypted_path(wallet_id)
            with open(encrypted_path, 'wb') as f:
                f.write(encrypted_data)
                
            return True
        except Exception as e:
            print(f"Error writing wallet data: {e}")
            return False
    
    def read_wallet_data(self, wallet_id: str) -> Optional[Dict[str, Any]]:
        """
        Read and decrypt wallet data from filesystem.
        
        Args:
            wallet_id: Unique identifier for the wallet
            
        Returns:
            Decrypted wallet data or None if not found/error
        """
        try:
            encrypted_path = self._get_encrypted_path(wallet_id)
            
            if not encrypted_path.exists():
                return None
                
            # Read encrypted data
            with open(encrypted_path, 'rb') as f:
                encrypted_data = f.read()
                
            # Decrypt the data
            decrypted_data = self._fernet.decrypt(encrypted_data)
            
            # Parse JSON
            return json.loads(decrypted_data.decode())
        except Exception as e:
            print(f"Error reading wallet data: {e}")
            return None
    
    def delete_wallet_data(self, wallet_id: str) -> bool:
        """
        Delete wallet data from filesystem.
        
        Args:
            wallet_id: Unique identifier for the wallet
            
        Returns:
            True if successful, False otherwise
        """
        try:
            encrypted_path = self._get_encrypted_path(wallet_id)
            if encrypted_path.exists():
                encrypted_path.unlink()
            return True
        except Exception as e:
            print(f"Error deleting wallet data: {e}")
            return False
    
    def list_wallet_ids(self) -> list[str]:
        """
        List all available wallet IDs (requires reverse lookup table).
        Note: This is a simplified implementation. In production, maintain a secure index.
        
        Returns:
            List of wallet IDs
        """
        # This would require an encrypted index file in production
        # For now, return empty list as wallet IDs are obfuscated
        return []
    
    def wallet_exists(self, wallet_id: str) -> bool:
        """
        Check if wallet data exists.
        
        Args:
            wallet_id: Unique identifier for the wallet
            
        Returns:
            True if wallet exists, False otherwise
        """
        encrypted_path = self._get_encrypted_path(wallet_id)
        return encrypted_path.exists()