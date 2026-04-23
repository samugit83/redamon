const express = require('express');

const router = express.Router();

// Tracking endpoint — accepts a ref query param and echoes a debug message.
// VECTOR: Reflected XSS — User-Agent header reflected in JSON body
//          (and ref param reflected as HTML inside the debug string for legacy compatibility)
router.get('/track', (req, res) => {
  const ref = req.query.ref || 'direct';
  const ua = req.headers['user-agent'] || 'unknown';
  res.setHeader('Content-Type', 'text/html; charset=utf-8');
  res.send(`<!DOCTYPE html><html><body style="font-family:system-ui;padding:24px;color:#0e1320;">
    <h2>Tracking pixel acknowledged</h2>
    <p>Source: ${ref}</p>
    <p>User-Agent: ${ua}</p>
    <p style="color:#6b7280;font-size:13px;">This endpoint is used by our newsletter to record opens. It is intentionally permissive about its inputs for legacy backwards compatibility.</p>
  </body></html>`);
});

router.post('/track', (req, res) => {
  const ref = req.query.ref || 'direct';
  const ua = req.headers['user-agent'] || 'unknown';
  res.json({ ok: true, ref, ua, t: Date.now() });
});

module.exports = router;
