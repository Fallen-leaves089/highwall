# syntax=docker/dockerfile:1.7
FROM python:3.15-slim-bookworm AS builder

ARG L5WALL_VERSION=0.2.1
ARG L5WALL_REVISION=unknown

WORKDIR /build
COPY pyproject.toml MANIFEST.in README.md LICENSE NOTICE ./
COPY l5wall ./l5wall

RUN python -m pip install --no-cache-dir --upgrade pip setuptools \
    && python -m pip wheel --no-cache-dir --wheel-dir /wheels .


FROM python:3.15-slim-bookworm

ARG L5WALL_VERSION=0.2.1
ARG L5WALL_REVISION=unknown

LABEL org.opencontainers.image.title="L5Wall" \
      org.opencontainers.image.description="Fail-closed TLS session policy and bounded HTTP/1.1 bridge for HighWall" \
      org.opencontainers.image.source="https://github.com/Fallen-leaves089/highwall/tree/main/subprojects/l5wall" \
      org.opencontainers.image.url="https://github.com/Fallen-leaves089/highwall" \
      org.opencontainers.image.licenses="Apache-2.0" \
      org.opencontainers.image.version="${L5WALL_VERSION}" \
      org.opencontainers.image.revision="${L5WALL_REVISION}"

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates \
    && rm -rf /var/lib/apt/lists/* \
    && groupadd --gid 10001 l5wall \
    && useradd --uid 10001 --gid l5wall --no-create-home --home-dir /nonexistent --shell /usr/sbin/nologin l5wall \
    && mkdir -p /etc/l5wall /usr/share/l5wall \
    && chown root:l5wall /etc/l5wall \
    && chmod 0750 /etc/l5wall

COPY --from=builder /wheels/*.whl /tmp/
RUN python -m pip install --no-cache-dir /tmp/*.whl \
    && rm -f /tmp/*.whl

COPY LICENSE NOTICE /usr/share/l5wall/

USER 10001:10001
EXPOSE 18443
STOPSIGNAL SIGTERM

HEALTHCHECK --interval=30s --timeout=5s --start-period=5s --retries=3 \
    CMD ["l5wall", "check", "-c", "/etc/l5wall/config.json"]

ENTRYPOINT ["l5wall"]
CMD ["serve", "-c", "/etc/l5wall/config.json"]
