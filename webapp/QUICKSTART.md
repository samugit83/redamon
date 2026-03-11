# 🚀 Quick Setup Guide

**TL;DR - One Command Setup:**

```bash
cd /workspaces/redamon/webapp
./setup.sh
npm run dev
```

Then visit `http://localhost:3000`

---

## What This Does

✅ Installs all dependencies  
✅ Sets up PostgreSQL connection  
✅ Creates database schema  
✅ Populates 7 sample users  
✅ Creates 8 projects (1 shared + 7 personal)  

---

## Sample Users Created

```
alice@example.com    - Alice Johnson (Owner of shared demo project)
bob@example.com      - Bob Smith
carol@example.com    - Carol Davis
dave@example.com     - Dave Wilson
eve@example.com      - Eve Martinez
frank@example.com    - Frank Anderson
grace@example.com    - Grace Lee
```

**No password required** - you can log in with any email directly in the UI.

---

## Database Commands

```bash
# Initial setup (one time)
./setup.sh

# Start development
npm run dev

# Database management
npm run db:push       # Apply schema changes
npm run db:seed       # Re-populate with sample data
npm run db:reset      # Wipe database (⚠️ destructive)
```

---

## Customize

Edit `prisma/seed.ts` to:
- Add/remove users
- Modify project defaults
- Change target domains
- Enable/disable scan modules

Then run: `npm run db:seed`

---

## Troubleshooting

**Database connection failed?**
- Ensure PostgreSQL is running: `docker-compose up -d`
- Check `.env.local` DATABASE_URL

**Want a fresh start?**
```bash
npm run db:reset
npm run db:seed
```

**See full setup guide:**
```bash
cat DB_SETUP.md
```
