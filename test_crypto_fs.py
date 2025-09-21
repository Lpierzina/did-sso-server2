"""
Tests for the encrypted file system.
"""

import pytest
import tempfile
import shutil
from pathlib import Path

from crypto_fs import EncryptedFileSystem


@pytest.fixture
def temp_storage():
    """Create temporary storage directory for tests."""
    temp_dir = tempfile.mkdtemp()
    yield temp_dir
    shutil.rmtree(temp_dir)


@pytest.fixture
def crypto_fs(temp_storage):
    """Create EncryptedFileSystem instance for testing."""
    return EncryptedFileSystem("test-master-key", temp_storage)


def test_write_and_read_wallet_data(crypto_fs):
    """Test writing and reading wallet data."""
    wallet_id = "test-wallet-123"
    test_data = {
        "wallet_id": wallet_id,
        "owner": "test-user",
        "did_document": {"id": "did:test:123"},
        "certificates": [],
        "metadata": {"created": "2024-01-01"}
    }
    
    # Write data
    assert crypto_fs.write_wallet_data(wallet_id, test_data)
    
    # Read data back
    retrieved_data = crypto_fs.read_wallet_data(wallet_id)
    assert retrieved_data is not None
    assert retrieved_data == test_data


def test_wallet_exists(crypto_fs):
    """Test wallet existence check."""
    wallet_id = "test-wallet-456"
    
    # Initially doesn't exist
    assert not crypto_fs.wallet_exists(wallet_id)
    
    # Write data
    test_data = {"test": "data"}
    crypto_fs.write_wallet_data(wallet_id, test_data)
    
    # Now exists
    assert crypto_fs.wallet_exists(wallet_id)


def test_delete_wallet_data(crypto_fs):
    """Test deleting wallet data."""
    wallet_id = "test-wallet-789"
    test_data = {"test": "data"}
    
    # Write and verify exists
    crypto_fs.write_wallet_data(wallet_id, test_data)
    assert crypto_fs.wallet_exists(wallet_id)
    
    # Delete and verify gone
    assert crypto_fs.delete_wallet_data(wallet_id)
    assert not crypto_fs.wallet_exists(wallet_id)
    assert crypto_fs.read_wallet_data(wallet_id) is None


def test_read_nonexistent_wallet(crypto_fs):
    """Test reading non-existent wallet."""
    result = crypto_fs.read_wallet_data("nonexistent-wallet")
    assert result is None


def test_different_master_keys():
    """Test that different master keys produce different encryption."""
    with tempfile.TemporaryDirectory() as temp_dir:
        fs1 = EncryptedFileSystem("key1", temp_dir)
        fs2 = EncryptedFileSystem("key2", temp_dir)
        
        wallet_id = "test-wallet"
        test_data = {"secret": "data"}
        
        # Write with first key
        fs1.write_wallet_data(wallet_id, test_data)
        
        # Try to read with second key - should not work
        result = fs2.read_wallet_data(wallet_id)
        assert result is None  # Decryption should fail


def test_filename_obfuscation(crypto_fs):
    """Test that wallet IDs are properly obfuscated in filenames."""
    wallet_id = "obvious-wallet-name"
    test_data = {"test": "data"}
    
    crypto_fs.write_wallet_data(wallet_id, test_data)
    
    # Check that no file contains the obvious wallet name
    storage_path = Path(crypto_fs.storage_path)
    files = list(storage_path.glob("*"))
    
    for file_path in files:
        assert wallet_id not in file_path.name
        assert file_path.suffix == ".enc"