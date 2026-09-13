# alpine/openssl ships OpenSSL 3.5.x. The stock alpine:3.20 package is 3.3.x,
# which does NOT accept -not_before/-not_after on `req -x509` -- and without
# those there is no way to mint the EXPIRED certificate this harness exists to
# serve.
FROM alpine/openssl:latest
COPY start.sh /start.sh
RUN chmod +x /start.sh
EXPOSE 993 636 995 465
ENTRYPOINT ["/start.sh"]
