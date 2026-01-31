# RedAmon Web Application

Production-ready Next.js 16 web application with Neo4j integration, containerized with Docker for scalable AWS deployment.

## Tech Stack

- **Framework**: Next.js 16.1 with App Router & Turbopack
- **Runtime**: Node.js 22
- **Database**: Neo4j 5.x (Graph Database)
- **Language**: TypeScript 5.7
- **UI**: React 19.2
- **Production**: Docker with multi-stage builds

## Project Structure

```
webapp/
├── src/
│   ├── app/                    # Next.js App Router
│   │   ├── api/               # API Routes
│   │   │   ├── health/        # Health check endpoint
│   │   │   └── neo4j/         # Neo4j query endpoint
│   │   ├── layout.tsx         # Root layout
│   │   ├── page.tsx           # Home page
│   │   └── globals.css        # Global styles
│   ├── components/            # React components
│   └── lib/
│       └── neo4j.ts           # Neo4j driver configuration
├── public/                    # Static assets
├── Dockerfile                 # Production multi-stage build
├── docker-compose.yml         # Production compose
└── package.json
```

---

## Prerequisites

**Neo4j must be running first.** This webapp connects to the existing Neo4j instance in `../graph_db/`.

```bash
# Start Neo4j from the graph_db folder
cd ../graph_db
docker compose up -d

# Verify Neo4j is running
# Neo4j Browser: http://localhost:7474
```

---

## Development Setup

```bash
# 1. Make sure Neo4j is running (see Prerequisites above)

# 2. Install dependencies
npm install

# 3. Copy and configure environment
cp .env.example .env.local
# Edit .env.local with your Neo4j password

# 4. Run development server (with hot reload)
npm run dev

# 5. Access the application
# Web App: http://localhost:3000
```

The development server uses Turbopack for fast refresh - changes to your code are reflected instantly.

---

## Production Build & Deployment

### Build Production Image

```bash
# Build the production image
docker build -t redamon-webapp:latest .

# Run production container locally
docker run -p 3000:3000 \
  --network graph_db_default \
  -e NEO4J_URI=bolt://redamon-neo4j:7687 \
  -e NEO4J_USER=neo4j \
  -e NEO4J_PASSWORD=your_password \
  redamon-webapp:latest
```

### Production with Docker Compose

```bash
# 1. Make sure Neo4j is running (from graph_db folder)
cd ../graph_db && docker compose up -d && cd ../webapp

# 2. Configure production environment
cp .env.example .env
# Edit .env with production values

# 3. Build and start services
docker compose up -d --build

# 4. View logs
docker compose logs -f webapp

# 5. Check health
curl http://localhost:3000/api/health
```

### Production Image Details

The production Dockerfile uses a multi-stage build:

1. **deps**: Installs production dependencies
2. **builder**: Builds the Next.js application
3. **runner**: Minimal runtime image (~150MB)

Features:
- Non-root user for security
- Standalone output for minimal image size
- Health check endpoint included
- Optimized for container orchestration

---

## AWS Deployment Guide

### Prerequisites

- AWS CLI configured
- ECR repository created
- ECS cluster or EKS cluster ready

### 1. Push to Amazon ECR

```bash
# Authenticate with ECR
aws ecr get-login-password --region us-east-1 | \
  docker login --username AWS --password-stdin \
  YOUR_ACCOUNT_ID.dkr.ecr.us-east-1.amazonaws.com

# Tag image
docker tag redamon-webapp:latest \
  YOUR_ACCOUNT_ID.dkr.ecr.us-east-1.amazonaws.com/redamon-webapp:latest

# Push image
docker push \
  YOUR_ACCOUNT_ID.dkr.ecr.us-east-1.amazonaws.com/redamon-webapp:latest
```

### 2. ECS Fargate Deployment

Create a task definition (`task-definition.json`):

```json
{
  "family": "redamon-webapp",
  "networkMode": "awsvpc",
  "requiresCompatibilities": ["FARGATE"],
  "cpu": "512",
  "memory": "1024",
  "executionRoleArn": "arn:aws:iam::YOUR_ACCOUNT:role/ecsTaskExecutionRole",
  "containerDefinitions": [
    {
      "name": "webapp",
      "image": "YOUR_ACCOUNT.dkr.ecr.us-east-1.amazonaws.com/redamon-webapp:latest",
      "portMappings": [
        {
          "containerPort": 3000,
          "protocol": "tcp"
        }
      ],
      "environment": [
        {"name": "NODE_ENV", "value": "production"},
        {"name": "NEO4J_URI", "value": "bolt://your-neo4j-endpoint:7687"}
      ],
      "secrets": [
        {
          "name": "NEO4J_PASSWORD",
          "valueFrom": "arn:aws:secretsmanager:us-east-1:YOUR_ACCOUNT:secret:redamon/neo4j"
        }
      ],
      "healthCheck": {
        "command": ["CMD-SHELL", "wget -q --spider http://localhost:3000/api/health || exit 1"],
        "interval": 30,
        "timeout": 5,
        "retries": 3,
        "startPeriod": 60
      },
      "logConfiguration": {
        "logDriver": "awslogs",
        "options": {
          "awslogs-group": "/ecs/redamon-webapp",
          "awslogs-region": "us-east-1",
          "awslogs-stream-prefix": "ecs"
        }
      }
    }
  ]
}
```

Deploy:
```bash
# Register task definition
aws ecs register-task-definition --cli-input-json file://task-definition.json

# Create service with ALB
aws ecs create-service \
  --cluster your-cluster \
  --service-name redamon-webapp \
  --task-definition redamon-webapp \
  --desired-count 2 \
  --launch-type FARGATE \
  --network-configuration "awsvpcConfiguration={subnets=[subnet-xxx],securityGroups=[sg-xxx],assignPublicIp=ENABLED}" \
  --load-balancers "targetGroupArn=arn:aws:elasticloadbalancing:...,containerName=webapp,containerPort=3000"
```

### 3. Auto Scaling Configuration

```bash
# Register scalable target
aws application-autoscaling register-scalable-target \
  --service-namespace ecs \
  --scalable-dimension ecs:service:DesiredCount \
  --resource-id service/your-cluster/redamon-webapp \
  --min-capacity 2 \
  --max-capacity 100

# Create scaling policy (target tracking)
aws application-autoscaling put-scaling-policy \
  --service-namespace ecs \
  --scalable-dimension ecs:service:DesiredCount \
  --resource-id service/your-cluster/redamon-webapp \
  --policy-name cpu-tracking \
  --policy-type TargetTrackingScaling \
  --target-tracking-scaling-policy-configuration '{
    "TargetValue": 70.0,
    "PredefinedMetricSpecification": {
      "PredefinedMetricType": "ECSServiceAverageCPUUtilization"
    },
    "ScaleOutCooldown": 60,
    "ScaleInCooldown": 120
  }'
```

### 4. Neo4j on AWS Options

**Option A: Amazon Neptune (Managed)**
- Fully managed graph database
- Compatible with openCypher (Neo4j query language)

**Option B: Neo4j AuraDB**
- Neo4j's managed cloud service
- Available on AWS Marketplace

**Option C: Self-hosted on EC2/EKS**
```bash
# EC2 with Docker
docker run -d \
  -p 7474:7474 -p 7687:7687 \
  -v /data/neo4j:/data \
  -e NEO4J_AUTH=neo4j/your_password \
  -e NEO4J_dbms_memory_heap_max__size=4G \
  neo4j:5-enterprise
```

---

## API Reference

### Health Check
```
GET /api/health
```
Returns service health status:
```json
{
  "status": "healthy",
  "timestamp": "2025-01-02T12:00:00.000Z",
  "services": {
    "neo4j": "connected"
  }
}
```

### Neo4j Status
```
GET /api/neo4j
```
Returns database connection status and node count.

### Execute Query
```
POST /api/neo4j
Content-Type: application/json

{
  "query": "MATCH (n) RETURN n LIMIT 10",
  "params": {}
}
```

---

## Environment Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `NEO4J_URI` | Neo4j connection URI | `bolt://localhost:7687` (dev) / `bolt://redamon-neo4j:7687` (Docker) |
| `NEO4J_USER` | Neo4j username | `neo4j` |
| `NEO4J_PASSWORD` | Neo4j password | (set in .env.local) |
| `NODE_ENV` | Environment mode | `development` |
| `PORT` | Application port | `3000` |

---

## Useful Commands

```bash
# Development
npm run dev              # Start dev server with Turbopack (hot reload)
npm run build            # Build for production
npm run start            # Start production server
npm run lint             # Run ESLint
npm run type-check       # Run TypeScript check

# Docker Production
docker compose up -d --build                           # Start prod
docker compose down                                    # Stop prod
docker compose ps                                      # List services
docker compose logs -f webapp                          # View logs

# Debugging
docker compose exec webapp sh                          # Shell into container

# Neo4j CLI (from graph_db folder)
cd ../graph_db && docker compose exec neo4j cypher-shell
```

---

## Troubleshooting

### Neo4j Connection Failed

1. Check if Neo4j is running: `cd ../graph_db && docker compose ps`
2. Verify credentials in `.env.local` match those in `../graph_db/.env`
3. Check Neo4j logs: `cd ../graph_db && docker compose logs neo4j`

### Build Fails with Memory Error

Increase Node.js memory limit:
```bash
NODE_OPTIONS="--max-old-space-size=4096" npm run build
```

### Permission Denied Errors (Docker)

The production image runs as non-root user. Ensure mounted volumes have correct permissions.

---

## Security Considerations

- Never commit `.env` or `.env.local` files
- Use AWS Secrets Manager for production credentials
- Enable Neo4j SSL/TLS in production
- Configure proper security groups for AWS deployment
- Implement rate limiting for API endpoints
- Use HTTPS with proper certificates (ALB handles this)
