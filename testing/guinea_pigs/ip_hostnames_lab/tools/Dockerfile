# iphn-tools: the outsider's packet-capture sidecar, and the throwaway client
# up.sh / set_moved.sh run INSIDE the lab network for their smoke checks, so
# the checks never depend on the host's resolver or route.
FROM alpine:3.20@sha256:d9e853e87e55526f6b2917df91a2115c36dd7c696a35be12163d44e6e2a4b6bc
RUN apk add --no-cache tcpdump bind-tools curl openssl
