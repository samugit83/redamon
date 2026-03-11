cd /workspaces/redamon/webapp
npm run dev#!/bin/bash

##############################################################################
# RedAmon Webapp - Automated Setup Script
# 
# This script handles the complete setup of the RedAmon webapp:
# - Installs dependencies
# - Initializes the database
# - Seeds sample data
##############################################################################

set -e  # Exit on error

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

echo -e "${BLUE}🚀 RedAmon Webapp Setup${NC}\n"

# Check if we're in the right directory
if [ ! -f "package.json" ]; then
    echo -e "${RED}❌ Error: package.json not found. Please run this script from the webapp directory.${NC}"
    exit 1
fi

# Step 1: Install dependencies
echo -e "${BLUE}📦 Step 1: Installing dependencies...${NC}"
if [ -d "node_modules" ]; then
    echo -e "${YELLOW}ℹ️  node_modules already exists. Skipping npm install.${NC}"
else
    npm install
    echo -e "${GREEN}✅ Dependencies installed${NC}\n"
fi

# Step 2: Check if .env.local exists
echo -e "${BLUE}🔧 Step 2: Checking environment configuration...${NC}"
if [ ! -f ".env.local" ]; then
    echo -e "${YELLOW}⚠️  .env.local not found. Creating default configuration...${NC}"
    cat > .env.local << 'EOF'
# PostgreSQL (Prisma)
DATABASE_URL="postgresql://redamon:redamon_secret@localhost:5432/redamon"

# Neo4j
NEO4J_URI=bolt://localhost:7687
NEO4J_USER=neo4j
NEO4J_PASSWORD=changeme123

# Backend services
RECON_ORCHESTRATOR_URL=http://localhost:8010
AGENT_API_URL=http://localhost:8090
AGENT_WS_URL=ws://localhost:8090/ws/agent
WEBAPP_URL=http://localhost:3000
EOF
    echo -e "${GREEN}✅ Created .env.local${NC}\n"
else
    echo -e "${GREEN}✅ .env.local exists${NC}\n"
fi

# Load environment variables
set -a
source .env.local
set +a

# Step 3: Apply database migrations
echo -e "${BLUE}📊 Step 3: Applying database migrations...${NC}"
npm run db:push
echo -e "${GREEN}✅ Migrations applied${NC}\n"

# Step 4: Seed the database
echo -e "${BLUE}🌱 Step 4: Seeding database with sample data...${NC}"
npm run db:seed
echo -e "${GREEN}✅ Database seeded${NC}\n"

# Summary
echo -e "${GREEN}✨ Setup Complete!${NC}\n"
echo -e "${BLUE}Next steps:${NC}"
echo "  1. Start the development server:"
echo -e "     ${YELLOW}npm run dev${NC}"
echo ""
echo "  2. Open your browser:"
echo -e "     ${YELLOW}http://localhost:3000${NC}"
echo ""
echo "  3. Login with any of the sample users:"
echo -e "     ${YELLOW}alice@example.com${NC}"
echo -e "     ${YELLOW}bob@example.com${NC}"
echo "     (and 5 more...)"
echo ""
echo -e "📖 For more details, see: ${YELLOW}DB_SETUP.md${NC}"
