import express from 'express';

export function createVaultRoutes(vault) {
  const router = express.Router();

  router.post('/grant', (req, res) => {
    try {
      const { scopeType, scopeIdParts, principal, perms } = req.body || {};
      if (!scopeType || !Array.isArray(scopeIdParts) || !principal) {
        return res.status(400).json({ success: false, error: 'scopeType, scopeIdParts[], principal required' });
      }
      vault.grant(scopeType, scopeIdParts, principal, perms || ['read']);
      res.json({ success: true });
    } catch (err) {
      res.status(500).json({ success: false, error: err?.message || 'grant failed' });
    }
  });

  router.post('/revoke', (req, res) => {
    try {
      const { scopeType, scopeIdParts, principal, perms } = req.body || {};
      if (!scopeType || !Array.isArray(scopeIdParts) || !principal) {
        return res.status(400).json({ success: false, error: 'scopeType, scopeIdParts[], principal required' });
      }
      vault.revoke(scopeType, scopeIdParts, principal, perms || ['read']);
      res.json({ success: true });
    } catch (err) {
      res.status(500).json({ success: false, error: err?.message || 'revoke failed' });
    }
  });

  router.get('/acl', (req, res) => {
    try {
      const scopeType = String(req.query.scopeType || '');
      const scopeIdParts = String(req.query.scopeIdParts || '').split(',').filter(Boolean);
      if (!scopeType || scopeIdParts.length === 0) {
        return res.status(400).json({ success: false, error: 'scopeType and scopeIdParts required' });
      }
      res.json({ success: true, acl: vault.getAcl(scopeType, scopeIdParts) });
    } catch (err) {
      res.status(500).json({ success: false, error: err?.message || 'acl failed' });
    }
  });

  return router;
}