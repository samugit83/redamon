# =============================================================================
# RedAmon GitHub Secret Hunter - Python Container
# =============================================================================
# This container runs the GitHub secret scanning tool, searching for
# exposed secrets, API keys, and credentials in GitHub repositories.
# =============================================================================

FROM python:3.12-slim

LABEL maintainer="RedAmon Project"
LABEL description="Python-based GitHub secret hunter for RedAmon"

# Set working directory
WORKDIR /app

# Install dependencies
COPY scanners/github_secret_hunt/requirements.txt /tmp/github_requirements.txt
RUN pip install --no-cache-dir -r /tmp/github_requirements.txt

# Copy project files (context is parent directory, so paths are relative to project root)
COPY scanners/github_secret_hunt/ ./github_secret_hunt/

# Copy graph_db module (for Neo4j integration)
COPY graph_db/ ./graph_db/
COPY recon_settings/ ./recon_settings/

# Create output directories
RUN mkdir -p github_secret_hunt/output

# Set Python path and ensure unbuffered output for log streaming
ENV PYTHONPATH=/app
ENV PYTHONUNBUFFERED=1

# Default command
CMD ["python", "github_secret_hunt/main.py"]
