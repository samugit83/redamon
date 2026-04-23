const express = require('express');
const { layout, BASE } = require('../lib/layout');
const store = require('../lib/store');

const router = express.Router();

// Profile view + edit
// VECTOR: Stored XSS — display name rendered into <h1> AND into <input value=""> on edit form
// VECTOR: Stored XSS — bio rendered in HTML body
// VECTOR: Stored XSS — avatarAlt rendered in alt="..." attribute
router.get('/profile', (req, res) => {
  const p = store.profile.get('default');
  const body = `
    <section>
      <div class="container">
        <h1 style="font-size:36px;">${p.display}</h1>
        <p class="muted">@${p.username}</p>
        <div style="display:grid; grid-template-columns: 1fr 2fr; gap:32px; margin-top:32px;">
          <div>
            <img src="${BASE}/static/avatar-placeholder.png" alt="${p.avatarAlt}" style="width:200px; height:200px; border-radius:8px; background:#fafbfc; display:block;" onerror="this.style.background='#e5e7eb'">
            <p class="muted" style="font-size:13px; margin-top:8px;">Avatar</p>
          </div>
          <div>
            <h3>Bio</h3>
            <p>${p.bio}</p>
            <a class="btn-ghost" href="${BASE}/account/profile/edit" style="margin-top:16px;">Edit profile</a>
          </div>
        </div>
      </div>
    </section>`;
  res.send(layout(`${p.display} — Profile`, body));
});

router.get('/profile/edit', (req, res) => {
  const p = store.profile.get('default');
  const body = `
    <section>
      <div class="container">
        <h1 style="font-size:32px;">Edit profile</h1>
        <form action="${BASE}/account/profile/save" method="POST" class="stacked">
          <div class="form-row"><label>Username</label><input type="text" name="username" value="${p.username}"></div>
          <div class="form-row"><label>Display name</label><input type="text" name="display" value="${p.display}"></div>
          <div class="form-row"><label>Bio</label><textarea name="bio">${p.bio}</textarea></div>
          <div class="form-row"><label>Avatar alt text (for accessibility)</label><input type="text" name="avatarAlt" value="${p.avatarAlt}"></div>
          <button type="submit">Save changes</button>
        </form>
      </div>
    </section>`;
  res.send(layout('Edit profile', body));
});

router.post('/profile/save', (req, res) => {
  const data = {
    username: (req.body.username || '').slice(0, 200),
    display: (req.body.display || '').slice(0, 200),
    bio: (req.body.bio || '').slice(0, 1000),
    avatarAlt: (req.body.avatarAlt || '').slice(0, 300),
  };
  store.profile.update('default', data);
  res.redirect(`${BASE}/account/profile`);
});

// Personal notes — stored XSS in JS string context (notes embedded in page bootstrap script)
router.get('/notes', (req, res) => {
  const notes = store.notes.list('default');
  const body = `
    <section>
      <div class="container">
        <h1 style="font-size:32px;">Personal notes</h1>
        <p class="lead">Lightweight notebook synced to your Argentum account.</p>
        <div id="notes-list" style="margin-top:24px;"></div>
        <h3 style="margin-top:32px;">New note</h3>
        <form action="${BASE}/account/notes/add" method="POST" class="stacked">
          <div class="form-row"><label>Title</label><input type="text" name="title" required maxlength="200"></div>
          <div class="form-row"><label>Body</label><textarea name="body" required maxlength="3000"></textarea></div>
          <div class="form-row"><label>Tag</label><input type="text" name="tag" placeholder="work / personal / ideas"></div>
          <button type="submit">Save note</button>
        </form>
      </div>
    </section>
    <script>
      // Notes are bootstrapped inline so the page is fast on first load.
      var NOTES = [
        ${notes.map(n => `{ id: ${n.id}, title: "${n.title.replace(/"/g, '\\"')}", body: "${n.body.replace(/"/g, '\\"').replace(/\n/g, '\\n')}", tag: "${(n.tag || '').replace(/"/g, '\\"')}" }`).join(',\n        ')}
      ];
      (function () {
        var container = document.getElementById('notes-list');
        if (NOTES.length === 0) { container.innerHTML = '<p class="muted">No notes yet.</p>'; return; }
        var html = '';
        NOTES.forEach(function (n) {
          html += '<div class="card" style="margin-bottom:12px;"><h4 style="margin:0 0 8px;">' + n.title + '</h4><p style="margin:0;">' + n.body + '</p><div class="meta"><span class="tag">' + (n.tag || 'untagged') + '</span></div></div>';
        });
        container.innerHTML = html;
      })();
    </script>`;
  res.send(layout('Personal notes', body));
});

router.post('/notes/add', (req, res) => {
  store.notes.add('default', {
    title: (req.body.title || 'Untitled').slice(0, 300),
    body: (req.body.body || '').slice(0, 5000),
    tag: (req.body.tag || '').slice(0, 80),
  });
  res.redirect(`${BASE}/account/notes`);
});

// Preferences page — DOM XSS via localStorage source piped into innerHTML
router.get('/preferences', (req, res) => {
  const body = `
    <section>
      <div class="container">
        <h1 style="font-size:32px;">Preferences</h1>
        <p class="lead">Customise the way Argentum tools look and behave for your account.</p>

        <div style="max-width:540px; margin-top:32px;">
          <div class="form-row"><label>Display nickname</label><input type="text" id="pref-nickname"></div>
          <div class="form-row" style="margin-top:14px;"><label>Personal greeting (rich text supported)</label><textarea id="pref-greeting"></textarea></div>
          <button id="pref-save" style="margin-top:14px;">Save preferences</button>
        </div>

        <h3 style="margin-top:48px;">Your dashboard greeting</h3>
        <div id="greeting-preview" style="margin-top:16px; padding:24px; background:#fafbfc; border:1px solid var(--line); border-radius:8px; min-height:80px;"></div>
      </div>
    </section>
    <script>
      (function () {
        var nickname = document.getElementById('pref-nickname');
        var greeting = document.getElementById('pref-greeting');
        var save = document.getElementById('pref-save');
        var preview = document.getElementById('greeting-preview');
        nickname.value = localStorage.getItem('arg_nickname') || '';
        greeting.value = localStorage.getItem('arg_greeting') || '';
        function renderPreview() {
          var name = localStorage.getItem('arg_nickname') || 'there';
          var msg = localStorage.getItem('arg_greeting') || '<em>Set a greeting to personalise your dashboard.</em>';
          preview.innerHTML = '<strong>Hello, ' + name + '!</strong><br>' + msg;
        }
        save.addEventListener('click', function () {
          localStorage.setItem('arg_nickname', nickname.value);
          localStorage.setItem('arg_greeting', greeting.value);
          renderPreview();
        });
        renderPreview();
      })();
    </script>`;
  res.send(layout('Preferences', body));
});

// Welcome page — DOM XSS via document.referrer
router.get('/welcome', (req, res) => {
  const body = `
    <section>
      <div class="container">
        <h1 style="font-size:32px;">Welcome back</h1>
        <p class="lead">Quick summary of what's new since you last visited.</p>
        <div id="welcome-source" class="banner" style="margin-top:32px;"></div>
        <div class="grid grid-2" style="margin-top:32px;">
          <div class="card"><h3>3 new comments</h3><p>On posts you authored or follow.</p></div>
          <div class="card"><h3>2 unread tickets</h3><p>From the support team.</p></div>
        </div>
      </div>
    </section>
    <script>
      (function () {
        var box = document.getElementById('welcome-source');
        var ref = document.referrer;
        if (ref) {
          // Show the user where they came from so they can navigate back easily
          box.innerHTML = 'You arrived from <a href="' + ref + '">' + ref + '</a>. Click to return there at any time.';
        } else {
          box.innerHTML = 'You arrived directly. Bookmark this page to come back.';
        }
      })();
    </script>`;
  res.send(layout('Welcome back', body));
});

module.exports = router;
