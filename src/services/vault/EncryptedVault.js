import crypto from 'crypto';

export class EncryptedVault {
  constructor({ mode = 'memory', masterKeyHex = '', fsDir = '.vault' } = {}) {
    this.mode = mode; // 'memory' or 'fs' (fs reserved for future)
    this.masterKey = masterKeyHex && /^[0-9a-fA-F]{64}$/.test(masterKeyHex)
      ? Buffer.from(masterKeyHex, 'hex')
      : crypto.randomBytes(32);

    this.store = new Map(); // blobId -> { enc, owner, meta }
    this.walletToDids = new Map(); // wallet -> Set(did)
    this.didToEntries = new Map(); // `${wallet}::${did}` -> [{ timestamp, files: Map(name->blobId), owner }]
    this.acl = new Map(); // scopeKey -> { read:Set(principal), write:Set(principal) }
  }

  scopeKey(type, parts) {
    return `${type}:${parts.join(':')}`;
  }

  grant(scopeType, parts, principal, perms = ['read']) {
    const key = this.scopeKey(scopeType, parts);
    if (!this.acl.has(key)) this.acl.set(key, { read: new Set(), write: new Set() });
    const entry = this.acl.get(key);
    for (const p of perms) {
      if (p === 'read') entry.read.add(principal.toLowerCase());
      if (p === 'write') entry.write.add(principal.toLowerCase());
    }
  }

  revoke(scopeType, parts, principal, perms = ['read']) {
    const key = this.scopeKey(scopeType, parts);
    if (!this.acl.has(key)) return;
    const entry = this.acl.get(key);
    for (const p of perms) {
      if (p === 'read') entry.read.delete(principal.toLowerCase());
      if (p === 'write') entry.write.delete(principal.toLowerCase());
    }
  }

  getAcl(scopeType, parts) {
    const key = this.scopeKey(scopeType, parts);
    const entry = this.acl.get(key);
    return entry ? { read: Array.from(entry.read), write: Array.from(entry.write) } : { read: [], write: [] };
  }

  has(scopeType, parts, principal, action, owner) {
    const p = (principal || '').toLowerCase();
    if (!p) return false;
    if (owner && p === owner.toLowerCase()) return true;

    const paths = [];
    if (scopeType === 'file') {
      paths.push(this.scopeKey('file', parts));
      paths.push(this.scopeKey('did', parts.slice(0, 2)));
      paths.push(this.scopeKey('wallet', parts.slice(0, 1)));
    } else if (scopeType === 'did') {
      paths.push(this.scopeKey('did', parts));
      paths.push(this.scopeKey('wallet', parts.slice(0, 1)));
    } else if (scopeType === 'wallet') {
      paths.push(this.scopeKey('wallet', parts));
    }

    for (const k of paths) {
      const entry = this.acl.get(k);
      if (!entry) continue;
      if (action === 'read' && entry.read.has(p)) return true;
      if (action === 'write' && entry.write.has(p)) return true;
    }
    return false;
  }

  encrypt(plainBuf) {
    const iv = crypto.randomBytes(12);
    const cipher = crypto.createCipheriv('aes-256-gcm', this.masterKey, iv);
    const ciphertext = Buffer.concat([cipher.update(plainBuf), cipher.final()]);
    const tag = cipher.getAuthTag();
    return Buffer.concat([iv, tag, ciphertext]).toString('base64');
  }

  decrypt(encBase64) {
    const buf = Buffer.from(encBase64, 'base64');
    const iv = buf.slice(0, 12);
    const tag = buf.slice(12, 28);
    const data = buf.slice(28);
    const decipher = crypto.createDecipheriv('aes-256-gcm', this.masterKey, iv);
    decipher.setAuthTag(tag);
    return Buffer.concat([decipher.update(data), decipher.final()]);
  }

  putBlob(owner, data, meta = {}) {
    const blobId = crypto.randomBytes(16).toString('hex');
    const enc = this.encrypt(Buffer.isBuffer(data) ? data : Buffer.from(String(data)));
    this.store.set(blobId, { enc, owner: (owner || '').toLowerCase(), meta });
    return blobId;
  }

  getBlob(blobId) {
    const entry = this.store.get(blobId);
    if (!entry) return null;
    return { owner: entry.owner, meta: entry.meta, data: this.decrypt(entry.enc) };
  }

  indexWalletDid(wallet, did) {
    const w = (wallet || '').toLowerCase();
    const d = (did || '').toLowerCase();
    if (!this.walletToDids.has(w)) this.walletToDids.set(w, new Set());
    this.walletToDids.get(w).add(d);
  }

  addDidEntry(wallet, did, timestamp, files, owner) {
    const key = `${wallet.toLowerCase()}::${did.toLowerCase()}`;
    if (!this.didToEntries.has(key)) this.didToEntries.set(key, []);
    this.didToEntries.get(key).push({ timestamp, files, owner: (owner || '').toLowerCase() });
  }

  listDids(wallet) {
    const w = (wallet || '').toLowerCase();
    return Array.from(this.walletToDids.get(w) || []);
  }

  listDidEntries(wallet, did) {
    const key = `${wallet.toLowerCase()}::${did.toLowerCase()}`;
    const arr = this.didToEntries.get(key) || [];
    return arr.slice().sort((a, b) => String(b.timestamp).localeCompare(String(a.timestamp)));
  }
}