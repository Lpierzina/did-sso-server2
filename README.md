# DID SSO Server with Encrypted File System

A secure Decentralized Identity (DID) Single Sign-On server with encrypted file system and comprehensive permission management for ADCS (Active Directory Certificate Services) storage.

## 🔐 Key Features

1. **Encrypted File System**: All wallet data is encrypted at rest using Fernet encryption
2. **Obfuscated Storage**: Wallet IDs are hashed to prevent filesystem enumeration  
3. **Role-Based Access Control**: Four permission levels (Guest, User, Admin, Superuser)
4. **Per-Wallet Permissions**: Granular access control for individual wallets
5. **Permission Management CLI**: Complete utility for managing user permissions
6. **RESTful API**: Full FastAPI-based web service for DID operations

## 🚀 Quick Start

### Prerequisites
```bash
pip install fastapi uvicorn cryptography pyjwt passlib python-multipart python-jose bcrypt click pydantic
```

### Running the Demo
```bash
# Run the comprehensive demo
python3 demo.py
```

### Starting the Server
```bash
# Start the DID SSO server
python3 main.py
```
The server will start on `http://localhost:8000`

### Using the CLI Utility
```bash
# Make CLI executable
chmod +x sso_admin.py

# Show help
./sso_admin.py --help

# Login as admin (get user ID from server startup)
./sso_admin.py login <admin_user_id>

# Create a new user
./sso_admin.py --token <token> create-user alice --role user

# Grant permissions
./sso_admin.py --token <token> grant <user_id> write --wallet-id wallet123

# List users
./sso_admin.py --token <token> list-users
```

## 📁 Project Structure

```
did-sso-server2/
├── main.py              # FastAPI web server and API endpoints
├── crypto_fs.py         # Encrypted file system implementation  
├── permissions.py       # Permission management system
├── sso_admin.py         # CLI utility for permission management
├── demo.py              # Comprehensive demonstration script
├── config.env           # Configuration template
├── requirements.txt     # Python dependencies
├── test_*.py            # Test suites
└── README.md            # This documentation
```

## 🔒 Security Architecture

### File System Encryption
- **Master Key**: All data encrypted with PBKDF2-derived keys
- **Fernet Encryption**: Symmetric encryption for wallet data
- **Filename Obfuscation**: SHA256 hashes prevent wallet ID enumeration
- **No Plain Text**: Wallet contents never stored in plain text

### Permission Model
```
Roles and Default Permissions:
├── GUEST      → No permissions
├── USER       → READ
├── ADMIN      → READ, WRITE  
└── SUPERUSER  → READ, WRITE, DELETE, ADMIN

Permission Types:
├── READ    → View wallet data
├── WRITE   → Create/modify wallets
├── DELETE  → Remove wallets
└── ADMIN   → Manage users and permissions

Permission Scope:
├── Global    → Applies to all operations
└── Per-Wallet → Specific to individual wallets
```

## 🌐 API Endpoints

### Authentication
- `POST /auth/login` - Login with user ID
- `POST /auth/create-user` - Create new user (admin only)
- `GET /auth/me` - Get current user info

### Wallet Operations
- `POST /wallets/{wallet_id}` - Create/update encrypted wallet
- `GET /wallets/{wallet_id}` - Read wallet data (with permissions)
- `DELETE /wallets/{wallet_id}` - Delete wallet (with permissions)

### Permission Management
- `POST /permissions/grant` - Grant permission to user
- `POST /permissions/revoke` - Revoke permission from user  
- `GET /permissions/users` - List all users (admin only)
- `GET /permissions/{user_id}` - Get user permissions

## 📊 Usage Examples

### Creating and Accessing Wallets

```python
import requests

# Login
response = requests.post("http://localhost:8000/auth/login", params={"user_id": "your_user_id"})
token = response.json()["access_token"]
headers = {"Authorization": f"Bearer {token}"}

# Create wallet
wallet_data = {
    "wallet_id": "alice_wallet_001",
    "owner": "alice@company.com", 
    "did_document": {"id": "did:example:alice123"},
    "certificates": [{"type": "X.509", "issuer": "CA-Company"}],
    "metadata": {"created": "2024-01-01"}
}

requests.post("http://localhost:8000/wallets/alice_wallet_001", json=wallet_data, headers=headers)

# Read wallet (if you have permissions)
response = requests.get("http://localhost:8000/wallets/alice_wallet_001", headers=headers)
print(response.json())
```

### Managing Permissions
```bash
# Grant read permission for specific wallet
./sso_admin.py --token $TOKEN grant alice_user_id read --wallet-id sensitive_wallet

# Grant global write permission
./sso_admin.py --token $TOKEN grant bob_user_id write

# Show user permissions
./sso_admin.py --token $TOKEN show-permissions alice_user_id
```

## 🧪 Testing

Run the test suites:
```bash
python3 -m pytest test_crypto_fs.py -v      # Test encrypted file system
python3 -m pytest test_permissions.py -v    # Test permission management
python3 -m pytest test_api.py -v           # Test API endpoints
```

## ⚙️ Configuration

Copy `config.env` to `.env` and modify:
```bash
# Security keys (CHANGE IN PRODUCTION!)
SECRET_KEY=your-jwt-secret-key
MASTER_KEY=your-encryption-master-key

# Server settings
HOST=0.0.0.0
PORT=8000
ACCESS_TOKEN_EXPIRE_MINUTES=30

# Storage
STORAGE_PATH=encrypted_storage
PERMISSIONS_FILE=permissions.json
```

## 🛡️ Security Considerations

1. **Change Default Keys**: Always use strong, unique keys in production
2. **HTTPS Only**: Use TLS/SSL for all API communications
3. **Key Rotation**: Implement regular key rotation procedures
4. **Backup Strategy**: Securely backup encrypted storage and permissions
5. **Audit Logging**: Monitor all permission changes and access attempts
6. **Network Security**: Restrict access to management endpoints

## 🔍 Troubleshooting

### Common Issues

**Server won't start:**
- Check if port 8000 is available
- Verify all dependencies are installed
- Check file permissions for storage directory

**Permission denied errors:**
- Verify user has required permissions
- Check JWT token is valid and not expired
- Ensure wallet-specific permissions are granted

**Encryption errors:**
- Verify MASTER_KEY is consistent
- Check storage directory is writable
- Ensure no file corruption

### Debug Mode
Set `DEBUG=true` in configuration for verbose logging.

## 📝 License

This project implements secure storage and permission management for DID-based SSO systems, ensuring ADCS data is properly encrypted and access-controlled.

## 🤝 Contributing

1. Test changes with `python3 demo.py`
2. Run all test suites
3. Update documentation for new features
4. Follow security best practices

---

**⚠️ Security Notice**: This implementation uses strong encryption and access controls, but should be reviewed by security professionals before production deployment.
