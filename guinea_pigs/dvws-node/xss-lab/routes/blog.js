const express = require('express');
const { layout, BASE, escapeHtml } = require('../lib/layout');
const store = require('../lib/store');

const router = express.Router();

const POSTS = [
  { slug: 'modern-growth', title: 'A pragmatic take on modern growth', author: 'Theo Park', read: '9 min read', body: `<p>The default growth playbook of the last decade — paid acquisition, CRO, lifecycle automation — is fraying. Channels that compounded reliably from 2014 to 2020 now require constant retuning to hold flat. Several of our clients have seen blended CAC double in eighteen months without any drop in product quality.</p><p>This essay is not a prediction about the death of paid media. It is a pragmatic take on what is actually working in 2024 across the dozen B2B engagements we ran in the last year. Most of it is unsexy.</p><h3>Stop optimising for the wrong loop</h3><p>The single most common mistake we see is teams optimising acquisition efficiency while their activation rate quietly degrades. Acquisition lift on a leaky bucket is worse than no lift — it makes the underlying problem harder to see.</p><p>Pull a chart of activation rate over the last twelve months for every product surface that matters. If the line is flat or falling, that is the loop to fix first. Channel work waits.</p>` },
  { slug: 'attribution-is-a-trap', title: 'Attribution is a trap (and what to do instead)', author: 'Mira Solovyev', read: '12 min read', body: `<p>Multi-touch attribution as a reporting layer is, at this point, mostly a security blanket. The vendors selling it know it. The CMOs paying for it know it. Everyone agrees the numbers are made up but they like the dashboard.</p><p>Here is what we recommend our clients use instead, in roughly increasing order of complexity.</p>` },
  { slug: 'onboarding-isnt-content', title: "Your onboarding isn't a content problem", author: 'Aki Tan', read: '7 min read', body: `<p>Most onboarding overhauls we are asked to advise on start with the wrong question — "what should our day-three email say?" — when the actual question is "why does it take three days to reach the activation moment in the first place?"</p>` },
];

// Blog index — clean
router.get('/', (req, res) => {
  const cards = POSTS.map(p => `
    <div class="card">
      <h3><a href="${BASE}/blog/post/${p.slug}" style="color:inherit;text-decoration:none;">${p.title}</a></h3>
      <p>${p.body.replace(/<[^>]+>/g, '').slice(0, 140)}…</p>
      <div class="meta"><span>${p.author}</span><span>${p.read}</span></div>
    </div>`).join('');
  const body = `
    <section>
      <div class="container">
        <h1 style="font-size:36px;">Insights</h1>
        <p class="lead">Practical notes from our consultants. New posts roughly fortnightly.</p>
        <form action="${BASE}/blog/search" method="GET" style="max-width:540px; margin:24px 0;">
          <input type="search" name="q" placeholder="Search the blog…" aria-label="Search the blog">
        </form>
        <div class="grid grid-2">${cards}</div>
        <div style="margin-top:32px;">
          <a class="btn-ghost" href="${BASE}/blog/category/strategy">Browse by category</a>
        </div>
      </div>
    </section>`;
  res.send(layout('Insights', body));
});

// VECTOR: Reflected XSS — HTML body context
// Search query echoed inside <h2>Results for "{q}"</h2>
router.get('/search', (req, res) => {
  const q = req.query.q || '';
  const matches = POSTS.filter(p =>
    q && (p.title.toLowerCase().includes(q.toLowerCase()) || p.body.toLowerCase().includes(q.toLowerCase()))
  );
  const matchHtml = matches.length === 0
    ? `<p class="muted" style="margin-top:24px;">No posts match your search.</p>`
    : matches.map(p => `
        <div class="card" style="margin-bottom:16px;">
          <h3><a href="${BASE}/blog/post/${p.slug}" style="color:inherit;text-decoration:none;">${p.title}</a></h3>
          <p>${escapeHtml(p.body.replace(/<[^>]+>/g, '').slice(0, 200))}…</p>
        </div>`).join('');
  const body = `
    <section>
      <div class="container">
        <a href="${BASE}/blog" class="muted" style="font-size:13px;">← All insights</a>
        <h1 style="font-size:32px; margin-top:8px;">Search results</h1>
        <p>Showing matches for "${q}"</p>
        <form action="${BASE}/blog/search" method="GET" style="max-width:540px; margin:24px 0;">
          <input type="search" name="q" value="${q}" placeholder="Refine your search…">
        </form>
        ${matchHtml}
      </div>
    </section>`;
  res.send(layout('Search', body));
});

// VECTOR: Reflected XSS — HTML attribute context (quoted)
// Category name echoed inside <input value="..."> AND inside <h1>
router.get('/category/:name', (req, res) => {
  const name = req.params.name || '';
  const body = `
    <section>
      <div class="container">
        <a href="${BASE}/blog" class="muted" style="font-size:13px;">← All insights</a>
        <h1 style="font-size:32px; margin-top:8px;">Category: ${name}</h1>
        <form action="${BASE}/blog/search" method="GET" style="max-width:540px; margin:24px 0;">
          <input type="search" name="q" placeholder="Refine within ${name}…" value="${name}">
        </form>
        <p class="muted">Showing posts tagged with this category.</p>
        <div class="grid grid-2" style="margin-top:24px;">
          ${POSTS.map(p => `
            <div class="card">
              <h3><a href="${BASE}/blog/post/${p.slug}" style="color:inherit;text-decoration:none;">${p.title}</a></h3>
              <p>${escapeHtml(p.body.replace(/<[^>]+>/g, '').slice(0, 140))}…</p>
            </div>`).join('')}
        </div>
      </div>
    </section>`;
  res.send(layout(`Category — ${name}`, body));
});

// Single post page with comments
// VECTOR: Stored XSS — comment body rendered into HTML body
// VECTOR: Stored XSS — comment author rendered into attribute (data-author="...")
router.get('/post/:slug', (req, res) => {
  const post = POSTS.find(p => p.slug === req.params.slug);
  if (!post) return res.status(404).send(layout('Not found', `<section><div class="container"><h1>Post not found</h1></div></section>`));

  const comments = store.comments.list(post.slug);
  const commentsHtml = comments.length === 0
    ? `<p class="muted">Be the first to comment.</p>`
    : comments.map(c => `
        <div class="comment" data-author="${c.author}">
          <div class="who">${c.author}</div>
          <div>${c.body}</div>
          <div class="when">${c.when}</div>
        </div>`).join('');

  const body = `
    <section>
      <div class="container">
        <article class="post">
          <a href="${BASE}/blog" class="muted" style="font-size:13px;">← All insights</a>
          <h1>${post.title}</h1>
          <p class="byline">By ${post.author} · ${post.read}</p>
          ${post.body}

          <h3 style="margin-top:48px;">Discussion</h3>
          <div class="comments">${commentsHtml}</div>

          <h4 style="margin-top:32px;">Leave a comment</h4>
          <form action="${BASE}/blog/post/${post.slug}/comment" method="POST" class="stacked">
            <div class="form-row">
              <label>Name</label>
              <input type="text" name="author" required maxlength="60" placeholder="Your name">
            </div>
            <div class="form-row">
              <label>Comment</label>
              <textarea name="body" required maxlength="2000" placeholder="Share your thoughts…"></textarea>
            </div>
            <button type="submit">Post comment</button>
          </form>
        </article>
      </div>
    </section>`;
  res.send(layout(post.title, body));
});

// Comment submission handler — intentionally stores raw HTML
router.post('/post/:slug/comment', (req, res) => {
  const post = POSTS.find(p => p.slug === req.params.slug);
  if (!post) return res.status(404).send('Not found');
  const author = (req.body.author || 'Anonymous').slice(0, 200);
  const commentBody = (req.body.body || '').slice(0, 5000);
  store.comments.add(post.slug, author, commentBody);
  res.redirect(`${BASE}/blog/post/${post.slug}#comments`);
});

module.exports = router;
