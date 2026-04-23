# Contributing to RedAmon

> *"Every scanner starts with a single packet."*

Welcome. Whether you write code, hunt bugs, test features, create videos, or improve docs — you are making offensive security tooling better for everyone. This guide tells you exactly how to get involved and what you get back for your work.

Before anything else, read the [DISCLAIMER.md](DISCLAIMER.md). This is a security tool — ethical and legal responsibility is non-negotiable.

---

## Table of Contents

- [Developer Guide](readmes/README.DEV.md)
- [Code of Conduct](#code-of-conduct)
- [Legal and Ethical Responsibilities](#legal-and-ethical-responsibilities)
- [Your First Contribution](#your-first-contribution)
- [Contribution Tracks](#contribution-tracks)
- [Contributor Ranks](#contributor-ranks)
- [Rewards Breakdown](#rewards-breakdown)
- [Architecture & Development Workflow](#architecture--development-workflow)
- [Reporting Issues](#reporting-issues)
- [Security Vulnerabilities](#security-vulnerabilities)
- [Hall of Fame](#hall-of-fame)
- [Maintainers](#maintainers)

---

## Code of Conduct

We keep this short because we trust you to be a decent human.

- Be respectful and considerate in all interactions
- Accept constructive criticism gracefully
- Focus on what is best for the community and project
- Show empathy toward other contributors

Harassment, trolling, or abusive behavior of any kind will not be tolerated.

---

## Legal and Ethical Responsibilities

RedAmon is a security assessment framework. **All contributors must adhere to ethical and legal standards.**

Before contributing, read the [DISCLAIMER.md](DISCLAIMER.md) in full. Key points:

- **Only target systems you own or have explicit written authorization to test.** Unauthorized access is illegal under the CFAA, Computer Misuse Act, EU Directive 2013/40/EU, and similar laws.
- **Never include real-world target data** in commits, issues, or pull requests.
- **Use safe testing environments** such as HackTheBox, TryHackMe, DVWA, or your own lab infrastructure.
- **Do not add capabilities** designed for malicious use, detection evasion, or unauthorized access.

Contributors are personally responsible for ensuring their use of this tool complies with all applicable laws in their jurisdiction.

---

## Your First Contribution

From zero to merged PR. Follow these steps.

### Step 0 — Set up the environment

```bash
# Fork the repo on GitHub, then:
git clone https://github.com/<your-username>/RedAmon.git
cd RedAmon

# Add the main repo as upstream (you'll need this to stay in sync)
git remote add upstream https://github.com/samugit83/redamon.git

# No .env file needed — all settings are configured from the webapp UI at /settings

# Enable dev mode (one-time, creates a gitignored override file)
cp docker-compose.dev.yml docker-compose.override.yml

# Build all images and start core services
docker compose --profile tools build
docker compose up -d postgres neo4j recon-orchestrator kali-sandbox agent webapp
```

Once the override file exists, all `docker compose` commands automatically use dev mode with Next.js hot-reload -- no `-f` flags needed.

Open `http://localhost:3000` -- you should see the dashboard. See the [README Quick Start](README.md#quick-start) for full details.

### Step 1 — Find something to work on

Three starting points, ordered by difficulty:

1. **Good First Issues** — look for the `good-first-issue` label on [GitHub Issues](https://github.com/samugit83/redamon/issues)
2. **"Up for Grabs" column** on the [Project Board](https://github.com/users/samugit83/projects/1)
3. **Bug you found** — file an issue first, then fix it
4. **Your own idea** — have a feature or improvement that's not on the roadmap? Just open a PR! All contributions are welcome, even if they're outside the current project plan

### Step 2 — Claim it

Comment on the issue: *"I'd like to work on this."* The maintainer will move it to **"In Progress"** on the board.

### Step 3 — Branch, build, test

```bash
git checkout master
git pull upstream master
git checkout -b feature/your-feature-name
```

Make your changes. Verify they work:

- **webapp changes:** `docker compose build webapp && docker compose up -d webapp`
- **recon-orchestrator changes:** code is volume-mounted — changes are instant
- **agent changes:** code is baked into the image — run `docker compose build agent && docker compose up -d agent`
- **Prisma schema changes:** `docker compose exec webapp npx prisma db push`

### Step 4 — Submit your PR

```bash
git push origin feature/your-feature-name
```

Open a Pull Request against `master`. The [PR template](.github/PULL_REQUEST_TEMPLATE.md) will guide you through what to include. The maintainer aims to respond within 48 hours.

### Step 5 — Celebrate

Your first merged PR earns you the **Scout** rank and a spot in the [Contributors Wall of Fame](README.md#contributors-wall-of-fame). Welcome to the team.

---

## Contribution Tracks

Pick the track that matches your skills and interests. You can contribute across multiple tracks — in fact, it's encouraged (see [Contributor Ranks](#contributor-ranks)).

### Bug Hunter

**Difficulty:** Beginner-friendly | **Components:** Any

Find and report bugs. Reproduce issues reported by others. Write detailed bug reports with logs (`docker compose logs <service>`). Every confirmed bug report counts toward your rank.

**Examples:**
- WebSocket disconnects during long recon scans
- Agent gets stuck in a loop on specific target configurations
- UI rendering issues on different browsers

### Testing & QA

**Difficulty:** Beginner to Intermediate | **Components:** `agentic/tests/`, `recon/tests/`

Test PRs before they merge — pull the branch, run it, verify it works. Test against your own lab infrastructure or authorized targets. Write test plans for new features. Use the [Test Report template](.github/ISSUE_TEMPLATE/test_report.yml) to submit your results.

**Examples:**
- Test a new recon module against your own lab VMs
- Verify a UI change works across Chrome, Firefox, Safari
- Write integration tests for a new API endpoint

### Feature Builder

**Difficulty:** Intermediate to Advanced | **Components:** `webapp/`, `recon_orchestrator/`, `agentic/`, `mcp/servers/`

Pick items from the [Roadmap Project Board](https://github.com/users/samugit83/projects/1). Major features include attack paths, cloud security, AD chains, and agent intelligence. Smaller features include new CPE mappings, new MCP tool servers, and new recon modules.

**Examples:**
- Implement a new attack path visualization
- Add a new MCP tool server for a security tool
- Build a new recon module (like the Shodan integration)

> **Note:** If you need to add a new Python import to `recon_orchestrator` or `agent`, check the Dockerfile first — the container must have the package or it will crash-loop.

> **Integrating a new tool?** We provide battle-tested AI prompts that guide you through every file and dependency layer — plus an iterative review workflow for zero-bug PRs. See **[AI-Assisted Development](https://github.com/samugit83/redamon/wiki/AI-Assisted-Development)** on the wiki.

### Docs & Wiki

**Difficulty:** Beginner-friendly | **Components:** `redamon.wiki/`, README files

Improve wiki pages. Write guides for specific features. Improve inline code documentation. Translate docs for non-English speakers.

**Examples:**
- Write a "How to write a custom MCP tool server" guide
- Improve the wiki with screenshots and walkthroughs
- Document undocumented project settings

### Security Research

**Difficulty:** Advanced | **Components:** `recon/`, `mcp/servers/`, `agentic/`

Add new recon modules. Integrate new OSINT data sources. Improve the agent's exploitation strategies. Contribute Nuclei templates.

**Examples:**
- Integrate a new OSINT API (Censys, FullHunt, etc.)
- Add new Nuclei templates for emerging CVEs
- Improve agent prompt strategies for specific exploit chains

### Content Creator

**Difficulty:** Any level | **Components:** YouTube, LinkedIn, blogs, social media

Share your RedAmon experience with the community — record videos, write about real-world engagements, or post case studies. This is one of the most impactful ways to contribute because it brings visibility to the project, helps new users understand what RedAmon can do, and demonstrates real-world value to the security community.

**What counts:**
- **Videos** — full attack chain demos, feature walkthroughs, setup guides, tool comparisons
- **Real-world case studies** — LinkedIn posts or blog articles describing how you used RedAmon in an actual engagement, internship, or lab environment
- **Writeups** — technical breakdowns of findings, workflows, or integrations you built with RedAmon

**Rules:**
- **Only use authorized infrastructure** — your own lab, HackTheBox, TryHackMe, or systems you have explicit written permission to test
- **Never show sensitive data** — blur or redact API keys, credentials, IPs of real targets, or any personal information
- **Respect privacy** — no footage of systems or data belonging to others without consent
- **Add a disclaimer** — include a visible note that the demo is performed on authorized targets only

**How to submit:**

1. Publish your content (YouTube, LinkedIn, blog, etc.)
2. Send an email to **devergo.sam@gmail.com** with:
   - **Subject:** `[RedAmon Showcase] <your content title>`
   - **Link** to the video, post, or article
   - **Your LinkedIn profile URL** (so we can tag you in the announcement)
   - **Your GitHub username**
   - A brief description of what the content covers
3. The maintainer reviews for policy compliance (authorized targets, no sensitive data, disclaimer present)
4. Once approved:
   - Your content is added to the [Community Showcase](README.md#community-showcase) in the README
   - You earn the **Broadcaster** rank and get added to the Wall of Fame
   - The maintainer posts about your content on LinkedIn and **tags your profile**

**What you get:**
- Your content featured in the project README — visible to every visitor
- LinkedIn visibility through the maintainer's post tagging your profile
- The exclusive **Broadcaster** rank (see [Contributor Ranks](#contributor-ranks))
- Showcase entries count toward your rank progression like any other contribution

---

## Contributor Ranks

Your contributions earn you ranks. The naming follows red team terminology because that's what we do.

| Rank | How to earn it | Key reward |
|------|---------------|------------|
| **Scout** | 5 merged PRs or 5 confirmed bug reports + 1 merged PR | Name in Wall of Fame |
| **Broadcaster** | 1 published YouTube video featuring RedAmon | Video in README showcase, name in Wall of Fame |
| **Hunter** | 10 merged PRs across at least 2 tracks | LinkedIn recommendation from maintainer |
| **Elite** | 15 merged PRs including at least 1 major roadmap feature | Blog co-authorship, private contributor channel |
| **Core** | Sustained contribution + demonstrated deep codebase knowledge | Push access, roadmap vote, release credits |

**How it works:**
- The maintainer assesses rank at each PR merge — no formal application needed
- Ranks are cumulative — you keep what you earned
- Bug reports count, not just code
- The "across 2+ tracks" requirement for Hunter (10 PRs) encourages breadth
- Core is by invitation — it requires trust and sustained engagement, not just a number
- You can request a rank review anytime by opening a discussion

---

## Rewards Breakdown

Every rank unlocks real rewards. No empty promises.

| Reward | Starting rank | Details |
|--------|--------------|---------|
| Wall of Fame recognition | Scout | Name + GitHub link in [Contributors Wall of Fame](README.md#contributors-wall-of-fame) |
| Video in README showcase | Broadcaster | Your video embedded in the [Video Showcase](README.md#video-showcase) section — visible to every visitor |
| LinkedIn recommendation | Hunter | The maintainer writes a personalized LinkedIn recommendation highlighting your open-source contributions |
| Early access | Hunter | Access to feature branches before public release |
| Blog co-authorship | Elite | Co-author technical writeups about features you built (published on project blog / Medium / dev.to) |
| Private contributor channel | Elite | Invitation to a private channel for contributor coordination and early discussions |
| Push access | Core | Direct push to non-protected branches, ability to merge PRs |
| Roadmap vote | Core | Participate in prioritization decisions for the project board |
| Release credit | Core | Named in CHANGELOG.md release notes |

---

## Architecture & Development Workflow

> For a comprehensive deep dive into the codebase — architecture, project layout, subsystem internals, and development checklists — see the **[Developer Guide](readmes/README.DEV.md)**.

RedAmon runs as a Docker Compose stack. Here's what each service does and how changes propagate:

| Service | Language | Directory | What it does |
|---------|----------|-----------|-------------|
| webapp | Next.js / TypeScript | `webapp/` | Frontend + API routes, Prisma ORM |
| recon-orchestrator | Python | `recon_orchestrator/` | Orchestrates the 6-phase recon pipeline |
| agent | Python | `agentic/` | AI agent for exploitation + triage |
| kali-sandbox | Kali Linux | `mcp/` | MCP tool servers (Metasploit, Nmap, Nuclei, Hydra) |
| postgres | PostgreSQL | `postgres_db/` | Project config, user settings |
| neo4j | Neo4j | `graph_db/` | Knowledge graph for all findings |
| gvm-* | OpenVAS / GVM | `gvm_scan/` | Vulnerability scanner (optional profile) |

**Hot-reload rules:**

| Service | How to apply changes |
|---------|---------------------|
| webapp | `docker compose build webapp && docker compose up -d webapp` |
| recon-orchestrator | Volume-mounted — changes are instant |
| agent | Code baked into image — `docker compose build agent && docker compose up -d agent` |
| Prisma schema | `docker compose exec webapp npx prisma db push` |

### Branching Strategy

Create branches from `master` using this naming convention:

| Prefix | Use case | Example |
|--------|----------|---------|
| `feature/` | New functionality | `feature/add-shodan-integration` |
| `fix/` | Bug fixes | `fix/websocket-reconnect` |
| `refactor/` | Code restructuring | `refactor/agent-state-management` |
| `docs/` | Documentation only | `docs/update-api-reference` |

### Commit Messages

We follow [Conventional Commits](https://www.conventionalcommits.org/):

| Prefix | Description |
|--------|-------------|
| `feat:` | New feature |
| `fix:` | Bug fix |
| `refactor:` | Code restructuring (no behavior change) |
| `docs:` | Documentation changes |
| `chore:` | Build process, tooling, dependency updates |
| `test:` | Adding or updating tests |

Keep commits **atomic and focused** — each commit should represent a single logical change.

### Pull Requests

When your work is ready:

1. **Push** your branch to your fork
2. **Open a Pull Request** against `master` — the [PR template](.github/PULL_REQUEST_TEMPLATE.md) auto-populates with the required sections
3. **Keep PRs focused** — large features should be broken into smaller, reviewable PRs when possible
4. **Ensure your branch is up to date** with `master` before requesting review:

   ```bash
   git fetch upstream
   git rebase upstream/master
   ```

---

## Reporting Issues

Use the structured issue templates — they guide you through everything we need:

- [**Bug Report**](https://github.com/samugit83/redamon/issues/new?template=bug_report.yml) — something is broken
- [**Feature Request**](https://github.com/samugit83/redamon/issues/new?template=feature_request.yml) — something should exist
- [**Test Report**](https://github.com/samugit83/redamon/issues/new?template=test_report.yml) — you tested a PR or feature

Each template includes component dropdowns, required fields, and placeholders to help you write a complete report. The better your report, the faster we can act on it.

---

## Security Vulnerabilities

If you discover a security vulnerability in RedAmon itself (not in target systems being scanned), **do not open a public issue**. Instead:

1. Use [GitHub Security Advisories](https://github.com/samugit83/redamon/security/advisories) to report privately
2. Include steps to reproduce and potential impact
3. Allow reasonable time for a fix before any public disclosure

For full details, see [SECURITY.md](SECURITY.md). We follow responsible disclosure and credit reporters in release notes.

---

## Hall of Fame

The [Contributors Wall of Fame](README.md#contributors-wall-of-fame) in README.md is the living leaderboard. It's updated with every rank promotion and tracks:

- Your name and GitHub profile
- Your current rank
- The tracks you've contributed to

This is visible to everyone who visits the repo — your work gets seen.

---

## Maintainers

**Samuele Giampieri** — creator and lead maintainer · [LinkedIn](https://www.linkedin.com/in/samuele-giampieri-b1b67597/) · [GitHub](https://github.com/samugit83) · [Devergo Labs](https://www.devergolabs.com/)

**Ritesh Gohil (L4stPL4Y3R)** — co-maintainer · [LinkedIn](https://www.linkedin.com/in/riteshgohil25/) · [GitHub](https://github.com/L4stPL4Y3R)

---

Questions? Open a discussion or issue on GitHub, or reach out to the maintainers.

We don't gatekeep. If you're interested in offensive security, AI, or just want to ship code that makes a difference — pull up a terminal and jump in.
