import express from 'express';
import cors from 'cors';
import { EncryptedVault } from './src/services/vault/EncryptedVault.js';
import { createVaultRoutes } from './src/routes/vaultRoutes.js';
import { createIpfsCompatRoutes } from './src/routes/ipfsCompatRoutes.js';

const app = express();
const port = process.env.PORT || 3000;

// CORS configuration
const corsOptions = {
  origin: process.env.CORS_ORIGIN || '*',
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization'],
  credentials: true
};

app.use(cors(corsOptions));
app.use(express.json());

// Create the vault
const vault = new EncryptedVault({
  mode: process.env.VAULT_MODE || 'memory',
  fsDir: process.env.VAULT_FS_DIR || '.vault',
  masterKeyHex: process.env.VAULT_MASTER_KEY || ''
});

// Mount routes early (after app.use(express.json()))
app.use('/api/vault', createVaultRoutes(vault));
app.use('/api/ipfs', createIpfsCompatRoutes(vault));

// TheOID IPFS URL endpoint
app.get('/api/theoid/ipfs-url', (req, res) => {
  res.json({ success: true, url: `vault://${process.env.VAULT_MODE || 'memory'}` });
});

// Health check endpoint
app.get('/health', (req, res) => {
  res.json({ success: true, status: 'healthy', timestamp: new Date().toISOString() });
});

// Root endpoint
app.get('/', (req, res) => {
  res.json({ 
    success: true, 
    message: 'DID SSO Server with Encrypted Vault', 
    version: '1.0.0',
    endpoints: [
      '/api/vault/grant',
      '/api/vault/revoke', 
      '/api/vault/acl',
      '/api/ipfs/upload',
      '/api/ipfs/dids/:walletAddress',
      '/api/ipfs/wallet/:walletAddress',
      '/api/ipfs/did/:did',
      '/api/ipfs/search',
      '/api/ipfs/upload-did-document',
      '/api/ipfs/list-dids',
      '/api/ipfs/get-private-key',
      '/api/ipfs/get-did-private-key',
      '/api/theoid/ipfs-url'
    ]
  });
});

// Error handling middleware
app.use((err, req, res, next) => {
  console.error('Error:', err);
  res.status(500).json({ success: false, error: 'Internal server error' });
});

// 404 handler
app.use((req, res) => {
  res.status(404).json({ success: false, error: 'Not found' });
});

app.listen(port, () => {
  console.log(`DID SSO Server running on port ${port}`);
  console.log(`Vault mode: ${process.env.VAULT_MODE || 'memory'}`);
  console.log(`CORS origin: ${process.env.CORS_ORIGIN || '*'}`);
});