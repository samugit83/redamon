# Scenarios E7 only: TruffleHog that waits SLOW_S seconds before it scans, so a
# live redamon-jsth-* sidecar can be paused and stopped. Built by
# `swap_image.sh slow` on top of the real image it parked; never shipped.
# The wrapper keeps the binary's path, so `--entrypoint trufflehog` reaches it.
FROM redamon-trufflehog:parked

ARG SLOW_S=300
ENV SLOW_S=${SLOW_S}
LABEL org.redamon.jslab.slow-wrapper="1"

USER root
# The sleep runs in the background so SIGTERM (docker stop) ends the wrapper at
# once, like the real binary, instead of waiting out the sleep as PID 1.
RUN mv /usr/local/bin/trufflehog /usr/local/bin/trufflehog.real \
 && printf '%s\n' '#!/bin/sh' \
      'trap "exit 143" TERM INT' \
      'sleep "${SLOW_S:-300}" & wait $!' \
      'exec /usr/local/bin/trufflehog.real "$@"' > /usr/local/bin/trufflehog \
 && chmod 0755 /usr/local/bin/trufflehog
USER trufflehog
