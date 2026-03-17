#!/bin/bash
# Redamon DigitalOcean Deployment Script

set -e

echo "=== Redamon Deployment to DigitalOcean ==="

# Check if .env exists
if [ ! -f .env ]; then
    echo "⚠️  Warning: .env file not found. Create it first with your API keys."
    echo "   Copy .env.example to .env and add your keys."
fi

# Pull latest code (if deploying from GitHub)
if [ -d .git ]; then
    git pull origin main
fi

# Build images
echo "🔨 Building Docker images..."
docker compose --profile tools build

# Start services (lightweight mode for 4GB droplets)
echo "🚀 Starting Redamon services..."
docker compose up -d postgres neo4j recon-orchestrator kali-sandbox agent webapp

# Check status
echo "⏳ Waiting for services to start..."
sleep 10
docker compose ps

echo "✅ Redamon deployed!"
echo "🌐 Access at: http://$(curl -s ifconfig.me):3000"
echo "⚙️  Configure settings at: http://$(curl -s ifconfig.me):3000/settings"
