# Database Setup & Initialization Guide

This guide walks you through setting up the RedAmon webapp with sample users and projects.

## Quick Start

### 1. **Prerequisites**
```bash
cd /workspaces/redamon/webapp

# Install dependencies
npm install

# Ensure PostgreSQL is running (via docker-compose)
docker-compose up -d
```

### 2. **Initialize the Database**

```bash
# Apply any pending migrations
npm run db:push

# Populate with sample data (7 users + projects)
npm run db:seed
```

### 3. **Start the Application**
```bash
npm run dev
```

Visit `http://localhost:3000`

---

## What Gets Created

### 👥 Users (7)
The seed script creates these sample users:

| Email | Name |
|-------|------|
| alice@example.com | Alice Johnson |
| bob@example.com | Bob Smith |
| carol@example.com | Carol Davis |
| dave@example.com | Dave Wilson |
| eve@example.com | Eve Martinez |
| frank@example.com | Frank Anderson |
| grace@example.com | Grace Lee |

### 📁 Projects

1. **Shared Demo Project** (`example.com`)
   - Owner: Alice Johnson
   - Target: example.com with subdomains (www, api, mail, staging)
   - Shared reference project for team testing
   - All scan modules enabled

2. **Personal Projects** (1 per user)
   - Each user gets their own project
   - Target: `target{N}.local`
   - Basic scan modules enabled

---

## Available Commands

```bash
# View all database commands
npm run db:push       # Apply migrations to database
npm run db:seed       # Populate with sample data
npm run db:reset      # Reset database to initial state (⚠️ destructive)
```

---

## Manual Project Creation

To create additional projects after initialization:

```tsx
// Use the Prisma Client in your code
import { PrismaClient } from '@prisma/client';

const prisma = new PrismaClient();

const project = await prisma.project.create({
  data: {
    userId: 'user-id-here',
    name: 'My Project',
    description: 'Project description',
    targetDomain: 'example.com',
    // ... other configuration fields
  },
});
```

---

## Customizing the Seed

Edit `prisma/seed.ts` to:
- Change user names/emails
- Modify project configurations
- Add more projects
- Set different default scan modules

Then re-run:
```bash
npm run db:seed
```

---

## Troubleshooting

### Database Connection Error
```bash
# Check if PostgreSQL is running
docker-compose ps

# Verify DATABASE_URL environment variable
echo $DATABASE_URL
```

### Migration Issues
```bash
# Check migration status
npx prisma migrate status

# Create migration for schema changes
npx prisma migrate dev --name "describe_your_change"
```

### Need Fresh Start
```bash
# ⚠️ CAUTION: This deletes all data
npm run db:reset

# Then re-seed if needed
npm run db:seed
```

---

## Next Steps

- Log in with any sample user email
- View the graph visualization at `/graph`
- Configure projects with your targets
- Run reconnaissance scans via the UI
