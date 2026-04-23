# Vulnerable Apache 2.4.25 for CVE-2017-3167 / CVE-2017-3169 testing
# WARNING: This is intentionally vulnerable - DO NOT use in production!

FROM debian:bullseye-slim

# Install build dependencies
ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update && apt-get install -y \
    build-essential \
    wget \
    libapr1-dev \
    libaprutil1-dev \
    libpcre3-dev \
    libssl-dev \
    && rm -rf /var/lib/apt/lists/*

# Download and compile vulnerable Apache 2.4.25
WORKDIR /tmp
RUN wget https://archive.apache.org/dist/httpd/httpd-2.4.25.tar.gz \
    && tar -xzf httpd-2.4.25.tar.gz \
    && cd httpd-2.4.25 \
    && ./configure \
        --prefix=/usr/local/apache2 \
        --enable-mods-shared=all \
        --enable-mpms-shared=all \
        --with-mpm=prefork \
        --enable-cgi \
        --enable-cgid \
        --enable-ssl \
        --enable-so \
        --enable-rewrite \
    && make \
    && make install \
    && cd .. \
    && rm -rf httpd-2.4.25 httpd-2.4.25.tar.gz

# Create www-data user (group already exists in Debian)
RUN useradd -r -g www-data www-data 2>/dev/null || true

# Copy configuration
COPY httpd.conf /usr/local/apache2/conf/httpd.conf

# Copy website content
COPY www/ /usr/local/apache2/htdocs/

# Copy CGI scripts
COPY cgi-bin/ /usr/local/apache2/cgi-bin/
RUN chmod +x /usr/local/apache2/cgi-bin/*

# Set permissions
RUN chown -R www-data:www-data /usr/local/apache2/htdocs \
    && chown -R www-data:www-data /usr/local/apache2/cgi-bin

EXPOSE 80 443

# Start Apache in foreground
CMD ["/usr/local/apache2/bin/httpd", "-D", "FOREGROUND"]
