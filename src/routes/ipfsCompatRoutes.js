import express from 'express';

export function createIpfsCompatRoutes(vault) {
  const router = express.Router();

  router.post('/upload', async (req, res) => {
    try {
      const { type, walletAddress, did, files, data, metadata } = req.body || {};
      const wallet = (walletAddress || '').toLowerCase();
      const didUniqueId = (did || '').toLowerCase();
      const timestamp = new Date().toISOString();
      if (!wallet || !didUniqueId) {
        return res.status(400).json({ success: false, error: 'walletAddress and did are required' });
      }

      const fileMap = new Map();
      if (Array.isArray(files)) {
        for (const f of files) {
          const name = String(f?.name || '');
          const content = typeof f?.content === 'string' ? Buffer.from(f.content, 'utf8') : Buffer.from([]);
          const blobId = vault.putBlob(wallet, content, { wallet, did: didUniqueId, name, timestamp });
          fileMap.set(name, blobId);
        }
      }
      if (data) {
        const name = type === 'did-compressed' ? 'compressed.did' : 'data.bin';
        const blobId = vault.putBlob(wallet, Buffer.from(String(data), 'utf8'), { wallet, did: didUniqueId, name, timestamp });
        fileMap.set(name, blobId);
      }
      if (metadata) {
        const blobId = vault.putBlob(wallet, Buffer.from(JSON.stringify(metadata)), { wallet, did: didUniqueId, name: 'metadata.json', timestamp });
        fileMap.set('metadata.json', blobId);
      }
      vault.indexWalletDid(wallet, didUniqueId);
      vault.addDidEntry(wallet, didUniqueId, timestamp, fileMap, wallet);
      return res.json({ success: true, id: Array.from(fileMap.values()).pop() || null, timestamp });
    } catch (err) {
      return res.status(500).json({ success: false, error: err?.message || 'upload failed' });
    }
  });

  router.get('/dids/:walletAddress', (req, res) => {
    try {
      const wallet = String(req.params.walletAddress || '').toLowerCase();
      const dids = vault.listDids(wallet).map(d => ({ didUniqueId: d }));
      return res.json({ success: true, dids });
    } catch {
      return res.status(500).json({ success: false, message: 'failed', dids: [] });
    }
  });

  router.get('/wallet/:walletAddress', (req, res) => {
    try {
      const wallet = String(req.params.walletAddress || '').toLowerCase();
      const dids = vault.listDids(wallet);
      return res.json({ success: true, walletData: { walletAddress: wallet, dids } });
    } catch {
      return res.status(500).json({ success: false, error: 'failed' });
    }
  });

  router.get('/did/:did', (req, res) => {
    try {
      const didParam = String(req.params.did || '').toLowerCase();
      const wallet = String(req.query.walletAddress || '').toLowerCase();
      if (!wallet || !didParam) return res.status(400).json({ success: false, error: 'walletAddress and did required' });
      const entries = vault.listDidEntries(wallet, didParam);
      if (entries.length === 0) return res.json({ success: true, didDocument: null });
      const latest = entries[0];
      // read permission
      if (!vault.has('did', [wallet, didParam], wallet, 'read', latest.owner)) {
        return res.status(403).json({ success: false, error: 'forbidden' });
      }
      for (const [name, blobId] of latest.files.entries()) {
        if (name === 'did-document.json') {
          const blob = vault.getBlob(blobId);
          try {
            const doc = JSON.parse(blob.data.toString('utf8'));
            return res.json({ success: true, didDocument: doc });
          } catch {}
        }
      }
      return res.json({ success: true, didDocument: null });
    } catch {
      return res.status(500).json({ success: false, error: 'failed' });
    }
  });

  router.get('/search', (req, res) => {
    try {
      const wallet = String(req.query.walletAddress || '').toLowerCase();
      const q = String(req.query.query || '').toLowerCase();
      const dids = vault.listDids(wallet);
      const results = dids.filter(d => d.includes(q)).map(d => ({ did: d }));
      return res.json({ success: true, results });
    } catch {
      return res.status(500).json({ success: false, results: [] });
    }
  });

  router.post('/upload-did-document', (req, res) => {
    try {
      const didDocument = req.body?.didDocument;
      if (!didDocument) return res.status(400).json({ success: false, error: 'didDocument required' });
      const didStr = String(didDocument.id || didDocument.did || '');
      const noPrefix = didStr.replace(/^did:autheo:/i, '');
      const [chainPart, addrPart] = noPrefix.split('-');
      const wallet = (addrPart || '').toLowerCase();
      const didUniqueId = `${(chainPart || '0x0').toLowerCase()}-${wallet}`;
      if (!wallet) return res.status(400).json({ success: false, error: 'could not parse wallet from did' });
      const timestamp = new Date().toISOString();
      const files = new Map();
      const blobId = vault.putBlob(wallet, Buffer.from(JSON.stringify(didDocument)), { wallet, did: didUniqueId, name: 'did-document.json', timestamp });
      files.set('did-document.json', blobId);
      vault.indexWalletDid(wallet, didUniqueId);
      vault.addDidEntry(wallet, didUniqueId, timestamp, files, wallet);
      return res.json({ success: true, cid: blobId });
    } catch {
      return res.status(500).json({ success: false, error: 'failed' });
    }
  });

  router.post('/list-dids', (req, res) => {
    try {
      const wallet = String(req.body?.walletAddress || '').toLowerCase();
      const dids = vault.listDids(wallet).map(d => ({ didUniqueId: d }));
      return res.json({ success: true, dids });
    } catch {
      return res.json({ success: false, dids: [] });
    }
  });

  router.post('/get-private-key', (req, res) => {
    try {
      const address = String(req.body?.address || '').toLowerCase();
      const dids = vault.listDids(address);
      for (const d of dids) {
        const entries = vault.listDidEntries(address, d);
        for (const e of entries) {
          for (const [name, blobId] of e.files.entries()) {
            if (/private\\.key$/i.test(name)) {
              const blob = vault.getBlob(blobId);
              return res.json({ success: true, privateKey: blob.data.toString('utf8') });
            }
          }
        }
      }
      return res.json({ success: false, error: 'not found' });
    } catch {
      return res.json({ success: false, error: 'failed' });
    }
  });

  router.post('/get-did-private-key', (req, res) => {
    try {
      const wallet = String(req.body?.walletAddress || '').toLowerCase();
      const did = String(req.body?.didUniqueId || '').toLowerCase();
      const entries = vault.listDidEntries(wallet, did);
      for (const e of entries) {
        for (const [name, blobId] of e.files.entries()) {
          if (/private\\.key$/i.test(name)) {
            const blob = vault.getBlob(blobId);
            return res.json({ success: true, privateKey: blob.data.toString('utf8') });
          }
        }
      }
      return res.json({ success: false, error: 'not found' });
    } catch {
      return res.json({ success: false, error: 'failed' });
    }
  });

  return router;
}