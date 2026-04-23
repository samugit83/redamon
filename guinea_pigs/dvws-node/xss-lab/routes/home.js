const express = require('express');
const { layout, BASE } = require('../lib/layout');

const router = express.Router();

router.get('/', (req, res) => {
  const body = `
    <section class="hero">
      <div class="container">
        <span class="tag">B2B growth consulting</span>
        <h1>Compounding growth, without the hand-waving.</h1>
        <p class="lead">Argentum Digital partners with ambitious B2B teams to design, ship, and operate revenue systems that actually compound — across product, marketing, and ops.</p>
        <div class="cta-row">
          <a class="btn-primary" href="${BASE}/contact">Book an intro call</a>
          <a class="btn-ghost" href="${BASE}/case-studies">Read case studies</a>
        </div>
      </div>
    </section>

    <section>
      <div class="container">
        <h2 class="section-title">What we do</h2>
        <p class="section-lead">A small senior team, embedded with yours, working on the loops that move the needle.</p>
        <div class="grid grid-3">
          <div class="card">
            <h3>Growth strategy</h3>
            <p>Quarterly planning, channel selection, and unit economics modelling for series A onward.</p>
            <a class="read-more" href="${BASE}/services">Explore services →</a>
          </div>
          <div class="card">
            <h3>Lifecycle &amp; CRM</h3>
            <p>Activation and retention programmes built on an event model your team can extend safely.</p>
            <a class="read-more" href="${BASE}/services">Explore services →</a>
          </div>
          <div class="card">
            <h3>Analytics engineering</h3>
            <p>Reliable measurement layers — dbt, warehouse-native attribution, and dashboards your CFO trusts.</p>
            <a class="read-more" href="${BASE}/services">Explore services →</a>
          </div>
        </div>
      </div>
    </section>

    <section>
      <div class="container">
        <h2 class="section-title">From the blog</h2>
        <p class="section-lead">Practical notes from our consultants — written for operators, not vendors.</p>
        <div class="grid grid-3">
          <div class="card">
            <span class="tag">Strategy</span>
            <h3 style="margin-top:10px;"><a href="${BASE}/blog/post/modern-growth" style="color:inherit;text-decoration:none;">A pragmatic take on modern growth</a></h3>
            <p>The default playbook is breaking. Here is what we recommend our clients run instead.</p>
            <div class="meta"><span>Theo Park</span><span>9 min read</span></div>
          </div>
          <div class="card">
            <span class="tag">Analytics</span>
            <h3 style="margin-top:10px;"><a href="${BASE}/blog/post/attribution-is-a-trap" style="color:inherit;text-decoration:none;">Attribution is a trap (and what to do instead)</a></h3>
            <p>Why we mostly stopped reporting MTA numbers to clients in 2023, and what we replaced them with.</p>
            <div class="meta"><span>Mira Solovyev</span><span>12 min read</span></div>
          </div>
          <div class="card">
            <span class="tag">Lifecycle</span>
            <h3 style="margin-top:10px;"><a href="${BASE}/blog/post/onboarding-isnt-content" style="color:inherit;text-decoration:none;">Your onboarding isn't a content problem</a></h3>
            <p>Activation almost never improves by writing more emails. It improves by removing decisions.</p>
            <div class="meta"><span>Aki Tan</span><span>7 min read</span></div>
          </div>
        </div>
      </div>
    </section>

    <section>
      <div class="container">
        <h2 class="section-title">Trusted by operators at</h2>
        <p class="muted" style="font-size:14px;">A selection of recent clients — full case studies available on request.</p>
        <div class="grid grid-3" style="margin-top:24px;">
          <div class="card"><strong>Fjord Robotics</strong><br><span class="muted" style="font-size:13px;">Series B, industrial automation</span></div>
          <div class="card"><strong>Bramwell &amp; Hale</strong><br><span class="muted" style="font-size:13px;">Series A, legaltech</span></div>
          <div class="card"><strong>Quayside Bio</strong><br><span class="muted" style="font-size:13px;">Series C, life sciences SaaS</span></div>
        </div>
      </div>
    </section>`;
  res.send(layout('Consulting and growth engineering for B2B', body));
});

router.get('/about', (req, res) => {
  const body = `
    <section>
      <div class="container">
        <h1 style="font-size:36px; letter-spacing:-.02em;">A small senior team based in London.</h1>
        <p class="lead" style="font-size:18px; color:var(--muted); max-width:680px;">We started Argentum in 2018 after a decade of in-house growth and analytics roles at companies like Stripe, Octopus Energy, Monzo, and Snowplow. Today we work with around twelve clients a year across Europe and North America.</p>
      </div>
    </section>
    <section>
      <div class="container">
        <h2 class="section-title">How we work</h2>
        <p class="section-lead">Engagements are typically twelve weeks, with a senior consultant fully embedded in your team. We do not staff junior consultants on client work.</p>
        <div class="grid grid-2">
          <div class="card">
            <h3>One senior partner per client</h3>
            <p>You will work with the person who scoped the engagement. We do not do bait-and-switch staffing.</p>
          </div>
          <div class="card">
            <h3>Outcomes, not retainers</h3>
            <p>We sell defined outcomes — a working system, a measurable lift, a transition handover — not generic monthly retainers.</p>
          </div>
        </div>
      </div>
    </section>
    <section>
      <div class="container">
        <h2 class="section-title">The team</h2>
        <div class="grid grid-3">
          <div class="card"><h3>Theo Park</h3><p>Founder. Previously growth at Stripe and Monzo.</p></div>
          <div class="card"><h3>Mira Solovyev</h3><p>Analytics engineering. Previously Snowplow and Octopus Energy.</p></div>
          <div class="card"><h3>Aki Tan</h3><p>Lifecycle and CRM. Previously Intercom and Customer.io.</p></div>
        </div>
      </div>
    </section>`;
  res.send(layout('About', body));
});

router.get('/case-studies', (req, res) => {
  const body = `
    <section>
      <div class="container">
        <h1 style="font-size:36px;">Selected case studies</h1>
        <p class="lead">Anonymised summaries of recent engagements. Full studies available under NDA.</p>
        <div class="grid grid-2" style="margin-top:32px;">
          <div class="card">
            <span class="tag">Fintech</span>
            <h3 style="margin-top:10px;">Series B fintech: 38% lift in activation</h3>
            <p>Rebuilt the first-week activation programme around three behavioural triggers. Eight-week engagement, sustained lift twelve months on.</p>
          </div>
          <div class="card">
            <span class="tag">Industrial</span>
            <h3 style="margin-top:10px;">Robotics manufacturer: enterprise sales motion</h3>
            <p>Designed and stood up an account-based outbound programme for ten target accounts in EMEA.</p>
          </div>
          <div class="card">
            <span class="tag">SaaS</span>
            <h3 style="margin-top:10px;">Vertical SaaS: ARR forecast accuracy ±3%</h3>
            <p>Replaced spreadsheet-based forecasting with a warehouse-native model in dbt.</p>
          </div>
          <div class="card">
            <span class="tag">Marketplace</span>
            <h3 style="margin-top:10px;">Two-sided marketplace: payback under 9 months</h3>
            <p>Re-allocated paid acquisition spend toward channels with positive contribution margin within nine months.</p>
          </div>
        </div>
      </div>
    </section>`;
  res.send(layout('Case studies', body));
});

router.get('/careers', (req, res) => {
  // Career landing — submission goes to /careers/apply (handled in support.js)
  const body = `
    <section>
      <div class="container">
        <h1 style="font-size:36px;">Join Argentum</h1>
        <p class="lead">We hire senior operators who want to work close to clients without the agency grind.</p>
      </div>
    </section>
    <section>
      <div class="container">
        <h2 class="section-title">Open roles</h2>
        <div class="grid grid-2">
          <div class="card">
            <h3>Senior growth consultant — London</h3>
            <p>Five+ years in B2B growth, analytics-literate, comfortable in front of a CFO.</p>
            <a class="read-more" href="${BASE}/careers/apply?role=senior-growth">Apply →</a>
          </div>
          <div class="card">
            <h3>Analytics engineer — remote (EU)</h3>
            <p>Deep dbt and warehouse experience, ideally with a B2B SaaS background.</p>
            <a class="read-more" href="${BASE}/careers/apply?role=analytics-engineer">Apply →</a>
          </div>
        </div>
      </div>
    </section>`;
  res.send(layout('Careers', body));
});

module.exports = router;
