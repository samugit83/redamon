// In-memory storage for stored/blind XSS surfaces.
// Resets on container restart — intentional, keeps the lab clean between runs.

const COMMENTS = [
  { id: 1, post: 'modern-growth', author: 'Theo Park', body: 'Great breakdown — the bit on attribution windows really lands.', when: '2 days ago' },
  { id: 2, post: 'modern-growth', author: 'Mira Solovyev', body: 'I would have added something on incremental lift but otherwise solid.', when: '1 day ago' },
];

const REVIEWS = [
  { id: 1, product: 'pulse', rating: 5, author: 'Lena from Acme', body: 'Cut our reporting time from days to hours.', when: '2024-09-12' },
  { id: 2, product: 'forge', rating: 4, author: 'David K.', body: 'Onboarding took longer than expected but very capable.', when: '2024-08-30' },
];

const PROFILES = new Map();
PROFILES.set('default', { username: 'jane.doe', display: 'Jane Doe', bio: 'Growth lead at a stealth-mode B2B SaaS.', avatarAlt: 'Jane wearing headphones' });

const NOTES = new Map();
NOTES.set('default', [
  { id: 1, title: 'Quarterly review prep', body: 'Pull funnel data for Q3 by region.', tag: 'work' },
]);

const CONTACT_MESSAGES = [];
const SUPPORT_TICKETS = [];
const CAREER_APPLICATIONS = [];

let nextCommentId = 100;
let nextReviewId = 100;
let nextNoteId = 100;
let nextContactId = 1;
let nextTicketId = 1;
let nextApplicationId = 1;

module.exports = {
  comments: {
    list: (post) => COMMENTS.filter(c => c.post === post),
    add: (post, author, body) => {
      const c = { id: nextCommentId++, post, author, body, when: 'just now' };
      COMMENTS.push(c);
      return c;
    },
  },
  reviews: {
    list: (product) => REVIEWS.filter(r => r.product === product),
    add: (product, rating, author, body) => {
      const r = { id: nextReviewId++, product, rating, author, body, when: new Date().toISOString().slice(0, 10) };
      REVIEWS.push(r);
      return r;
    },
  },
  profile: {
    get: (id = 'default') => PROFILES.get(id) || PROFILES.get('default'),
    update: (id, data) => {
      const existing = PROFILES.get(id) || {};
      PROFILES.set(id, { ...existing, ...data });
      return PROFILES.get(id);
    },
  },
  notes: {
    list: (id = 'default') => NOTES.get(id) || [],
    add: (id, note) => {
      const list = NOTES.get(id) || [];
      const n = { id: nextNoteId++, ...note };
      list.push(n);
      NOTES.set(id, list);
      return n;
    },
  },
  contact: {
    list: () => CONTACT_MESSAGES,
    add: (msg) => {
      const m = { id: nextContactId++, ...msg, received: new Date().toISOString() };
      CONTACT_MESSAGES.push(m);
      return m;
    },
  },
  support: {
    list: () => SUPPORT_TICKETS,
    add: (t) => {
      const r = { id: nextTicketId++, ...t, opened: new Date().toISOString(), status: 'open' };
      SUPPORT_TICKETS.push(r);
      return r;
    },
  },
  careers: {
    list: () => CAREER_APPLICATIONS,
    add: (a) => {
      const r = { id: nextApplicationId++, ...a, applied: new Date().toISOString() };
      CAREER_APPLICATIONS.push(r);
      return r;
    },
  },
};
