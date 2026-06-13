# plex-forward-auth — stdlib only, no pip deps. Tiny + size-optimized.
FROM python:3.12-alpine
WORKDIR /app
COPY plex_forward_auth.py /app/plex_forward_auth.py
ENV PORT=8056
EXPOSE 8056
# No build artifacts, no deps to strip — the image is just python + one file.
HEALTHCHECK --interval=30s --timeout=4s --start-period=5s \
  CMD wget -qO- http://127.0.0.1:8056/healthz || exit 1
USER 1000:1000
ENTRYPOINT ["python", "-u", "/app/plex_forward_auth.py"]
