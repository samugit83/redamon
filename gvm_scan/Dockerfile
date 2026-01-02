# =============================================================================
# RedAmon Vulnerability Scanner - Python Container
# =============================================================================
# This container runs the GVM Python scanner script, connecting to gvmd
# via Unix socket to create and execute vulnerability scans.
# =============================================================================

FROM python:3.12-slim

LABEL maintainer="RedAmon Project"
LABEL description="Python-based GVM vulnerability scanner for RedAmon"

# Set working directory
WORKDIR /app

# Install dependencies (only python-gvm needed for scanner)
COPY gvm_scan/requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy project files (context is parent directory, so paths are relative to project root)
COPY params.py .
COPY gvm_scan/ ./gvm_scan/

# Create output directory
RUN mkdir -p gvm_scan/output recon/output

# Set Python path
ENV PYTHONPATH=/app

# Default command
CMD ["python", "gvm_scan/main.py"]

