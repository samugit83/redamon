const express = require('express');
const { layout, BASE } = require('../lib/layout');
const store = require('../lib/store');

const router = express.Router();

// Internal moderation queue — loaded periodically by the in-cluster headless
// browser. Renders every recent submission with whatever HTML was stored.
// Not linked from the public site.
router.get('/inbox', (req, res) => {
  // Only allow loopback access
  const ip = (req.ip || '').replace('::ffff:', '');
  const allowed = ip === '127.0.0.1' || ip === '::1' || req.headers['x-internal-bot'] === '1';
  if (!allowed) {
    return res.status(404).send('Not found');
  }

  const contact = store.contact.list().slice(-50);
  const tickets = store.support.list().slice(-50);
  const careers = store.careers.list().slice(-50);

  const renderContact = contact.map(m => `
    <div class="card" style="margin-bottom:12px;">
      <div class="who">${m.name} &lt;${m.email}&gt; — ${m.company || 'no company'} (${m.interest})</div>
      <div style="margin-top:8px;">${m.message}</div>
      <div class="when">${m.received}</div>
    </div>`).join('');

  const renderTickets = tickets.map(t => `
    <div class="card" style="margin-bottom:12px;">
      <div class="who">${t.email} — ${t.product} — ${t.subject}</div>
      <div style="margin-top:8px;">${t.description}</div>
      ${t.console ? `<pre style="background:#0e1320;color:#e5e7eb;padding:12px;border-radius:6px;margin-top:8px;overflow-x:auto;">${t.console}</pre>` : ''}
      <div class="when">${t.opened}</div>
    </div>`).join('');

  const renderCareers = careers.map(c => `
    <div class="card" style="margin-bottom:12px;">
      <div class="who">${c.name} — ${c.role} — <a href="${c.link}">${c.link}</a></div>
      <h4 style="margin:8px 0 4px;">Motivation</h4>
      <div>${c.motivation}</div>
      <h4 style="margin:8px 0 4px;">Past project</h4>
      <div>${c.project}</div>
      <div class="when">${c.applied}</div>
    </div>`).join('');

  const body = `
    <section>
      <div class="container">
        <h1 style="font-size:32px;">Moderation queue</h1>
        <p class="muted">Internal staff view — auto-refreshes every 30s.</p>

        <h2 style="margin-top:32px;">Contact (${contact.length})</h2>
        ${renderContact || '<p class="muted">No new messages.</p>'}

        <h2 style="margin-top:32px;">Support tickets (${tickets.length})</h2>
        ${renderTickets || '<p class="muted">No open tickets.</p>'}

        <h2 style="margin-top:32px;">Career applications (${careers.length})</h2>
        ${renderCareers || '<p class="muted">No new applications.</p>'}
      </div>
    </section>`;
  res.send(layout('Moderation queue', body, { noNav: true }));
});

module.exports = router;
