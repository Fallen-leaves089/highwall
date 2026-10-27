# syntax=docker/dockerfile:1.7
FROM python:3.12-slim-bookworm

ARG HIGHWALL_VERSION=0.7.1
ARG HIGHWALL_REVISION=unknown

LABEL org.opencontainers.image.title="HighWall" \
      org.opencontainers.image.description="Fail-closed HTTP/1.1 application-layer reverse proxy and security gateway" \
      org.opencontainers.image.source="https://github.com/Fallen-leaves089/highwall" \
      org.opencontainers.image.url="https://github.com/Fallen-leaves089/highwall" \
      org.opencontainers.image.licenses="Apache-2.0" \
      org.opencontainers.image.version="${HIGHWALL_VERSION}" \
      org.opencontainers.image.revision="${HIGHWALL_REVISION}"

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PYTHONPATH=/app

RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates \
    && rm -rf /var/lib/apt/lists/* \
    && groupadd --gid 10001 highwall \
    && useradd --uid 10001 --gid highwall --no-create-home --home-dir /nonexistent --shell /usr/sbin/nologin highwall \
    && mkdir -p /app /etc/highwall /var/lib/highwall /usr/share/highwall \
    && chown -R highwall:highwall /app /var/lib/highwall \
    && chown root:highwall /etc/highwall \
    && chmod 0750 /etc/highwall /var/lib/highwall

WORKDIR /app
COPY --chown=highwall:highwall highwall ./highwall
COPY LICENSE NOTICE /usr/share/highwall/

USER 10001:10001
EXPOSE 18090
STOPSIGNAL SIGTERM

ENTRYPOINT ["python", "-m", "highwall"]
CMD ["serve", "-c", "/etc/highwall/config.json"]
