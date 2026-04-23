const express = require('express');
const { layout, BASE } = require('../lib/layout');
const store = require('../lib/store');

const router = express.Router();

// Contact form — staff inbox reads submissions periodically (admin bot)
router.get('/contact', (req, res) => {
  const product = req.query.product || '';
  const body = `
    <section>
      <div class="container">
        <h1 style="font-size:36px;">Contact us</h1>
        <p class="lead">Tell us about your team, your goals, and what you have tried so far. A senior partner will reply within one business day.</p>
        <form action="${BASE}/contact/send" method="POST" class="stacked" style="margin-top:32px; max-width:640px;">
          <div class="form-row"><label>Your name</label><input type="text" name="name" required maxlength="120"></div>
          <div class="form-row"><label>Work email</label><input type="email" name="email" required maxlength="200"></div>
          <div class="form-row"><label>Company</label><input type="text" name="company" maxlength="200"></div>
          <div class="form-row"><label>Interested in</label>
            <select name="interest">
              <option value="consulting" ${product ? '' : 'selected'}>Consulting engagement</option>
              <option value="pulse" ${product === 'pulse' ? 'selected' : ''}>Pulse</option>
              <option value="forge" ${product === 'forge' ? 'selected' : ''}>Forge</option>
              <option value="meridian" ${product === 'meridian' ? 'selected' : ''}>Meridian</option>
              <option value="other">Other</option>
            </select>
          </div>
          <div class="form-row"><label>Message</label><textarea name="message" required maxlength="5000"></textarea></div>
          <button type="submit">Send message</button>
        </form>
      </div>
    </section>`;
  res.send(layout('Contact us', body));
});

router.post('/contact/send', (req, res) => {
  store.contact.add({
    name: (req.body.name || 'Anonymous').slice(0, 200),
    email: (req.body.email || '').slice(0, 300),
    company: (req.body.company || '').slice(0, 200),
    interest: (req.body.interest || '').slice(0, 100),
    message: (req.body.message || '').slice(0, 10000),
  });
  const body = `
    <section>
      <div class="container">
        <h1 style="font-size:32px;">Thanks — we will be in touch.</h1>
        <p class="lead">A senior partner reviews every inbound enquiry by hand. You can expect a reply within one business day.</p>
        <p style="margin-top:32px;"><a class="btn-ghost" href="${BASE}/">Back to the homepage</a></p>
      </div>
    </section>`;
  res.send(layout('Message sent', body));
});

// Support ticket portal — staff reviews tickets in their inbox
router.get('/support', (req, res) => {
  const body = `
    <section>
      <div class="container">
        <h1 style="font-size:36px;">Support</h1>
        <p class="lead">Open a ticket and our customer success team will respond within four working hours.</p>
        <form action="${BASE}/support/open" method="POST" class="stacked" style="margin-top:32px; max-width:640px;">
          <div class="form-row"><label>Account email</label><input type="email" name="email" required maxlength="200"></div>
          <div class="form-row"><label>Product</label>
            <select name="product">
              <option value="pulse">Pulse</option>
              <option value="forge">Forge</option>
              <option value="meridian">Meridian</option>
              <option value="consulting">Consulting engagement</option>
            </select>
          </div>
          <div class="form-row"><label>Subject</label><input type="text" name="subject" required maxlength="200"></div>
          <div class="form-row"><label>Describe the issue</label><textarea name="description" required maxlength="10000" placeholder="What happened? What did you expect?"></textarea></div>
          <div class="form-row"><label>Browser console output (optional)</label><textarea name="console" maxlength="5000" placeholder="Paste any error messages from your browser console."></textarea></div>
          <button type="submit">Open ticket</button>
        </form>
      </div>
    </section>`;
  res.send(layout('Support', body));
});

router.post('/support/open', (req, res) => {
  store.support.add({
    email: (req.body.email || '').slice(0, 300),
    product: (req.body.product || '').slice(0, 100),
    subject: (req.body.subject || 'Untitled').slice(0, 300),
    description: (req.body.description || '').slice(0, 20000),
    console: (req.body.console || '').slice(0, 10000),
  });
  const body = `
    <section>
      <div class="container">
        <h1 style="font-size:32px;">Ticket opened</h1>
        <p class="lead">Our customer success team is on it. We will reply to your registered email shortly.</p>
        <p style="margin-top:32px;"><a class="btn-ghost" href="${BASE}/">Back to the homepage</a></p>
      </div>
    </section>`;
  res.send(layout('Ticket opened', body));
});

// Career application form — HR reviews applications
router.get('/careers/apply', (req, res) => {
  const role = req.query.role || 'general';
  const body = `
    <section>
      <div class="container">
        <h1 style="font-size:36px;">Apply</h1>
        <p class="lead">Role: <code>${role}</code></p>
        <form action="${BASE}/careers/apply" method="POST" class="stacked" style="margin-top:32px; max-width:640px;">
          <input type="hidden" name="role" value="${role}">
          <div class="form-row"><label>Full name</label><input type="text" name="name" required maxlength="200"></div>
          <div class="form-row"><label>Email</label><input type="email" name="email" required maxlength="200"></div>
          <div class="form-row"><label>LinkedIn or portfolio URL</label><input type="text" name="link" maxlength="400"></div>
          <div class="form-row"><label>Why Argentum?</label><textarea name="motivation" required maxlength="5000"></textarea></div>
          <div class="form-row"><label>Notable past project</label><textarea name="project" maxlength="5000"></textarea></div>
          <button type="submit">Submit application</button>
        </form>
      </div>
    </section>`;
  res.send(layout('Apply', body));
});

router.post('/careers/apply', (req, res) => {
  store.careers.add({
    role: (req.body.role || 'general').slice(0, 100),
    name: (req.body.name || 'Anonymous').slice(0, 200),
    email: (req.body.email || '').slice(0, 300),
    link: (req.body.link || '').slice(0, 600),
    motivation: (req.body.motivation || '').slice(0, 10000),
    project: (req.body.project || '').slice(0, 10000),
  });
  const body = `
    <section>
      <div class="container">
        <h1 style="font-size:32px;">Application received</h1>
        <p class="lead">Thanks for applying. Our hiring team reviews every application personally. We will be in touch.</p>
        <p style="margin-top:32px;"><a class="btn-ghost" href="${BASE}/">Back to the homepage</a></p>
      </div>
    </section>`;
  res.send(layout('Application received', body));
});

module.exports = router;
