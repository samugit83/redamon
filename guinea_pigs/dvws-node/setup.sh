#!/bin/bash
# Install Docker and deploy RedAmon HackLab target environment
set -e

echo "=== Installing Docker ==="

# Detect OS and install Docker
if [ -f /etc/os-release ]; then
    . /etc/os-release
    OS=$ID
fi

if [ "$OS" = "ubuntu" ] || [ "$OS" = "debian" ]; then
    sudo apt-get update
    sudo apt-get install -y docker.io docker-compose git
elif [ "$OS" = "amzn" ] || [ "$OS" = "fedora" ] || [ "$OS" = "rhel" ]; then
    sudo dnf install -y docker git
    sudo curl -sL "https://github.com/docker/compose/releases/latest/download/docker-compose-$(uname -s)-$(uname -m)" -o /usr/local/bin/docker-compose
    sudo chmod +x /usr/local/bin/docker-compose
fi

sudo systemctl start docker
sudo systemctl enable docker

echo "=== Cleaning up Docker space ==="
cd ~
if [ -d dvws-node ]; then
    cd dvws-node
    sudo docker-compose down --volumes --remove-orphans 2>/dev/null || true
    cd ~
fi
# Stop and remove any other running containers (previous guinea pigs, etc.)
sudo docker stop $(sudo docker ps -aq) 2>/dev/null || true
sudo docker system prune -a -f --volumes

echo "=== Cloning DVWS-Node ==="
rm -rf ~/dvws-node
git clone https://github.com/snoopysecurity/dvws-node.git ~/dvws-node
cd ~/dvws-node

# If the operator scp'd the xss-lab directory alongside setup.sh, move it in.
if [ -d ~/xss-lab ]; then
    echo "=== Importing Argentum site (xss-lab) ==="
    rm -rf ~/dvws-node/xss-lab
    mv ~/xss-lab ~/dvws-node/xss-lab
fi

echo "=== Creating additional containers ==="

# Tomcat container
mkdir -p ~/dvws-node/tomcat-rce
cat > ~/dvws-node/tomcat-rce/Dockerfile << 'DOCKERFILE'
FROM vulhub/tomcat:8.5.19
RUN cd /usr/local/tomcat/conf \
    && LINE=$(nl -ba web.xml | grep '<load-on-startup>1' | awk '{print $1}') \
    && ADDON="<init-param><param-name>readonly</param-name><param-value>false</param-value></init-param>" \
    && sed -i "$LINE i $ADDON" web.xml
EXPOSE 8080
DOCKERFILE

# vsftpd container
mkdir -p ~/dvws-node/vsftpd-backdoor
cat > ~/dvws-node/vsftpd-backdoor/Dockerfile << 'DOCKERFILE'
FROM ubuntu:20.04
ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update \
    && apt-get install -y build-essential wget libcap-dev \
    && rm -rf /var/lib/apt/lists/*
RUN wget -q https://github.com/nikdubois/vsftpd-2.3.4-infected/archive/refs/heads/vsftpd_original.tar.gz -O /tmp/vsftpd.tar.gz \
    && tar xzf /tmp/vsftpd.tar.gz -C /tmp \
    && cd /tmp/vsftpd-2.3.4-infected-vsftpd_original \
    && chmod +x vsf_findlibs.sh \
    && sed -i 's|`./vsf_findlibs.sh`|-lcrypt -lcap|' Makefile \
    && make \
    && cp vsftpd /usr/local/sbin/vsftpd \
    && chmod 755 /usr/local/sbin/vsftpd \
    && rm -rf /tmp/vsftpd*
RUN mkdir -p /var/ftp /etc/vsftpd /var/run/vsftpd/empty \
    && useradd -r -d /var/ftp -s /usr/sbin/nologin ftp 2>/dev/null; true
RUN printf "listen=YES\nanonymous_enable=YES\nlocal_enable=YES\nwrite_enable=YES\nsecure_chroot_dir=/var/run/vsftpd/empty\n" > /etc/vsftpd.conf
EXPOSE 21 6200
CMD ["/usr/local/sbin/vsftpd", "/etc/vsftpd.conf"]
DOCKERFILE

# Landing page with legal terms (served by nginx at / and /legal)
echo "=== Creating legal landing page ==="
mkdir -p ~/dvws-node/landing
cat > ~/dvws-node/landing/index.html << 'LANDING_HTML'
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>RedAmon HackLab -- Research Target</title>
<style>
  * { margin: 0; padding: 0; box-sizing: border-box; }
  body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; background: #0a0a0a; color: #e0e0e0; line-height: 1.6; }
  .container { max-width: 860px; margin: 0 auto; padding: 2rem 1.5rem; }
  h1 { color: #ff4444; font-size: 1.8rem; margin-bottom: 0.3rem; }
  .subtitle { color: #888; font-size: 1rem; margin-bottom: 2rem; }
  .warning-box { background: #1a0000; border: 1px solid #ff4444; border-radius: 8px; padding: 1rem 1.2rem; margin-bottom: 2rem; }
  .warning-box strong { color: #ff6666; }
  h2 { color: #ff6666; font-size: 1.2rem; margin: 1.8rem 0 0.8rem; border-bottom: 1px solid #222; padding-bottom: 0.4rem; }
  .info-box { background: #111; border: 1px solid #222; border-radius: 8px; padding: 1rem 1.2rem; margin: 1rem 0; font-size: 0.95rem; }
  ol { padding-left: 1.5rem; }
  ol li { margin-bottom: 0.6rem; }
  ol li strong { color: #ffaaaa; }
  .consequences { background: #1a0000; border-left: 3px solid #ff4444; padding: 0.8rem 1rem; margin: 1.2rem 0; font-size: 0.9rem; }
  .footer { margin-top: 2.5rem; padding-top: 1rem; border-top: 1px solid #222; color: #555; font-size: 0.8rem; text-align: center; }
  a { color: #ff8888; text-decoration: none; }
  a:hover { text-decoration: underline; }
  .badge { display: inline-block; background: #2a0000; border: 1px solid #ff4444; color: #ff6666; padding: 0.2rem 0.6rem; border-radius: 4px; font-size: 0.75rem; font-weight: bold; margin-right: 0.4rem; }
</style>
</head>
<body>
<div class="container">

<h1>RedAmon HackLab</h1>
<p class="subtitle">Research Target Server -- gpigs.devergolabs.com</p>

<div class="warning-box">
  <strong>WARNING:</strong> This server is a dedicated research target for authorized security testing with <a href="https://github.com/samugit83/redamon">RedAmon</a> only. All traffic is logged and monitored. By accessing any service on this server, you accept the Rules of Engagement below.
</div>

<div class="info-box">
  This server hosts multiple services as part of the <a href="https://github.com/samugit83/redamon">RedAmon</a> HackLab research environment. The RedAmon AI agent is designed to autonomously discover and map the attack surface. No additional information about the target is provided here intentionally -- the agent must perform its own reconnaissance.
</div>

<h2>Rules of Engagement</h2>
<ol>
  <li><strong>RedAmon-only testing.</strong> This server is provided exclusively for testing with the <a href="https://github.com/samugit83/redamon">RedAmon</a> framework. Manual exploitation, third-party scanners, and automated tools other than RedAmon are not authorized.</li>
  <li><strong>Scope.</strong> Only interact with services hosted on this server. All other IPs and infrastructure behind this server are out of scope.</li>
  <li><strong>No lateral movement.</strong> Do not attempt to pivot from this server to other systems, networks, or cloud infrastructure.</li>
  <li><strong>No denial of service.</strong> Do not perform load testing, resource exhaustion, or any action intended to degrade availability.</li>
  <li><strong>No data exfiltration beyond the server.</strong> Do not exfiltrate data to external servers, set up reverse shells to your own infrastructure, or establish persistent backdoors.</li>
  <li><strong>No modification of the environment.</strong> Do not delete databases, drop tables, modify other users' data, or alter running services in ways that affect other testers.</li>
  <li><strong>Responsible disclosure.</strong> If you discover a vulnerability in RedAmon itself (not in the target), report it via <a href="https://github.com/samugit83/redamon/issues">GitHub Issues</a>.</li>
  <li><strong>Legal compliance.</strong> You are solely responsible for ensuring your testing complies with all applicable laws in your jurisdiction. Unauthorized access to computer systems is illegal in most countries.</li>
  <li><strong>No warranty / liability.</strong> This server is provided "as is" for educational and research purposes. Devergolabs assumes no liability for any damages arising from your use. Access may be revoked at any time without notice.</li>
  <li><strong>Logging and monitoring.</strong> All traffic to this server is logged. IP addresses and request data are recorded for security monitoring and abuse prevention.</li>
</ol>

<div class="consequences">
  <strong>Violations</strong> will result in immediate IP ban and may be reported to the relevant ISP or law enforcement authority.
</div>

<h2>Get Started</h2>
<p style="margin-top:0.5rem;">
  <span class="badge">1</span> Install <a href="https://github.com/samugit83/redamon">RedAmon</a> &nbsp;
  <span class="badge">2</span> Create a project targeting this server &nbsp;
  <span class="badge">3</span> Run the recon pipeline &nbsp;
  <span class="badge">4</span> Let the AI agent attack &nbsp;
  <span class="badge">5</span> Record and <a href="https://github.com/samugit83/redamon/wiki/RedAmon-HackLab#community-sessions">submit your session</a>
</p>

<div class="footer">
  <a href="https://github.com/samugit83/redamon">RedAmon</a> &middot;
  <a href="https://github.com/samugit83/redamon/wiki/RedAmon-HackLab">HackLab Wiki</a> &middot;
  <a href="https://devergolabs.com">Devergolabs</a>
  <br/>Last updated: 2026-04-04
</div>

</div>
</body>
</html>
LANDING_HTML

# Nginx config -- serves landing page at / and /legal, proxies API traffic to dvws-node
cat > ~/dvws-node/landing/nginx.conf << 'NGINX_CONF'
server {
    listen 80;
    client_max_body_size 16M;

    # Landing page with legal terms
    location = / {
        root /usr/share/nginx/html;
        try_files /index.html =404;
    }
    location = /legal {
        root /usr/share/nginx/html;
        try_files /index.html =404;
    }

    # Argentum Digital site (Node.js sidecar on port 3001)
    location /argentum/ {
        proxy_pass http://argentum:3001;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        proxy_http_version 1.1;
    }

    # Proxy everything else to DVWS-Node
    location / {
        proxy_pass http://web:80;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
    }
}
NGINX_CONF

# docker-compose.override.yml -- expose databases + add extra containers + nginx landing
# All services use restart: unless-stopped so they come back after EC2 reboot
cat > ~/dvws-node/docker-compose.override.yml << 'OVERRIDE'
version: '3'
services:

  # Nginx landing page + reverse proxy
  landing:
    image: nginx:alpine
    container_name: gpigs-landing
    ports:
      - "80:80"
    volumes:
      - ./landing/index.html:/usr/share/nginx/html/index.html:ro
      - ./landing/nginx.conf:/etc/nginx/conf.d/default.conf:ro
    depends_on:
      - web
      - argentum
    restart: unless-stopped

  # Argentum Digital sidecar (Node.js + headless Chromium for the moderation queue)
  argentum:
    build: ./xss-lab
    container_name: gpigs-argentum
    expose:
      - "3001"
    restart: unless-stopped

  # Base DVWS services -- add restart policy
  web:
    restart: unless-stopped

  dvws-mongo:
    ports:
      - "27017:27017"
    restart: unless-stopped

  dvws-mysql:
    ports:
      - "3306:3306"
    restart: unless-stopped

  tomcat-rce:
    build: ./tomcat-rce
    container_name: gpigs-tomcat
    ports:
      - "8080:8080"
    restart: unless-stopped

  log4shell:
    image: ghcr.io/christophetd/log4shell-vulnerable-app:latest
    container_name: gpigs-log4shell
    ports:
      - "8888:8080"
    restart: unless-stopped

  vsftpd:
    build: ./vsftpd-backdoor
    container_name: gpigs-vsftpd
    ports:
      - "21:21"
      - "6200:6200"
    restart: unless-stopped
OVERRIDE

# Move web app off port 80 (nginx landing takes over)
# App is reachable via nginx proxy and directly on host port 8081
sed -i 's/"80:80"/"8081:80"/' ~/dvws-node/docker-compose.yml

echo "=== Building and starting all containers ==="
sudo docker-compose up -d --build

PUBLIC_IP=$(curl -s ifconfig.me 2>/dev/null || echo '<IP>')

echo ""
echo "=== DONE ==="
echo ""
echo "RedAmon HackLab deployed successfully."
echo "  Landing page:  http://${PUBLIC_IP}/"
echo "  All containers set to restart: unless-stopped"
echo ""
echo "All services will auto-restart after EC2 reboot."
