# DID SSO Server - Security Checklist

## 🔒 Pre-Production Security Checklist

### Encryption & Keys
- [ ] Change `SECRET_KEY` from default value
- [ ] Change `MASTER_KEY` from default value  
- [ ] Use cryptographically strong keys (>32 chars, random)
- [ ] Store keys securely (not in source code)
- [ ] Implement key rotation procedures
- [ ] Backup master keys securely

### Authentication & Authorization
- [ ] Implement proper user authentication (not just user_id)
- [ ] Add password hashing for user accounts
- [ ] Configure appropriate JWT expiration times
- [ ] Review and test all permission combinations
- [ ] Implement session management
- [ ] Add rate limiting to login endpoints

### Network Security
- [ ] Deploy with HTTPS/TLS only
- [ ] Configure proper CORS policies
- [ ] Use reverse proxy (nginx/Apache) in production
- [ ] Implement request rate limiting
- [ ] Add IP whitelisting for admin endpoints
- [ ] Configure firewall rules

### Data Protection
- [ ] Verify encrypted storage path permissions (700)
- [ ] Set up secure backup procedures for encrypted data
- [ ] Implement audit logging for all operations
- [ ] Add data retention policies
- [ ] Test encryption key recovery procedures
- [ ] Verify no plaintext data in logs

### Access Control
- [ ] Review default user roles and permissions
- [ ] Test permission inheritance and conflicts
- [ ] Implement principle of least privilege
- [ ] Add administrative approval for privileged operations
- [ ] Test emergency access procedures
- [ ] Document permission escalation procedures

### Infrastructure Security
- [ ] Keep all dependencies updated
- [ ] Run security scans on codebase
- [ ] Configure secure file permissions
- [ ] Disable debug mode in production
- [ ] Set up proper logging and monitoring
- [ ] Implement health checks and alerts

### Compliance & Governance
- [ ] Document all security controls
- [ ] Create incident response procedures  
- [ ] Set up compliance monitoring
- [ ] Regular security audits
- [ ] Staff security training
- [ ] Legal review for data handling

## 🚨 Critical Security Warnings

⚠️  **NEVER USE DEFAULT KEYS IN PRODUCTION**
⚠️  **ALWAYS USE HTTPS IN PRODUCTION**
⚠️  **REGULARLY BACKUP ENCRYPTION KEYS**
⚠️  **MONITOR ALL ADMIN OPERATIONS**
⚠️  **TEST DISASTER RECOVERY PROCEDURES**

## 📋 Security Testing Checklist

### Encryption Testing
- [ ] Test data encryption/decryption with correct keys
- [ ] Verify data is unreadable with wrong keys
- [ ] Test filename obfuscation (no wallet IDs visible)
- [ ] Verify encrypted files cannot be opened directly
- [ ] Test key rotation procedures

### Permission Testing  
- [ ] Test all role-based permission combinations
- [ ] Verify wallet-specific permissions work correctly
- [ ] Test permission denial scenarios
- [ ] Verify admin-only operations are restricted
- [ ] Test permission persistence after restart

### API Security Testing
- [ ] Test without authentication tokens
- [ ] Test with expired/invalid tokens
- [ ] Test CORS configuration
- [ ] Test input validation on all endpoints
- [ ] Verify error messages don't leak information
- [ ] Test rate limiting functionality

### Penetration Testing
- [ ] SQL injection tests (if database added)
- [ ] Cross-site scripting (XSS) tests
- [ ] Authentication bypass attempts  
- [ ] Authorization bypass attempts
- [ ] File system access attempts
- [ ] Brute force attack tests

## 🔍 Monitoring & Alerting

### Log What to Monitor
- All authentication attempts (success/failure)
- Permission grants and revocations
- Wallet creation, access, and deletion
- Admin operations
- Failed decryption attempts
- System errors and exceptions

### Alert Conditions
- Multiple failed login attempts
- Unauthorized access attempts
- Permission escalation attempts
- Unusual data access patterns
- System errors or crashes
- Disk space issues in storage directory

## 📞 Incident Response

### In Case of Security Breach
1. Isolate affected systems immediately
2. Preserve logs and evidence
3. Assess scope of breach
4. Notify stakeholders per policy
5. Implement containment measures
6. Begin recovery procedures
7. Conduct post-incident review

### Emergency Contacts
- Security Team: [CONTACT INFO]
- System Administrator: [CONTACT INFO]
- Legal/Compliance: [CONTACT INFO]
- Management: [CONTACT INFO]

---

**Remember**: Security is an ongoing process, not a one-time setup. 
Regularly review and update these security measures.