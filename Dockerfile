FROM python:3.12-slim AS builder

WORKDIR /build
COPY . .

RUN pip install --no-cache-dir build && \
    python -m build --wheel --no-isolation && \
    python -m build --sdist --no-isolation

FROM python:3.12-slim

LABEL org.opencontainers.image.title="VINA"
LABEL org.opencontainers.image.description="AI-assisted security automation framework"
LABEL org.opencontainers.image.licenses="MIT"
LABEL org.opencontainers.image.source="https://github.com/anomalyco/vina"

RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates \
    curl \
    && rm -rf /var/lib/apt/lists/*

RUN groupadd -r -g 1001 vina && \
    useradd -r -u 1001 -g vina -m -d /home/vina -s /sbin/nologin vina

RUN install -d -o vina -g vina /var/lib/vina /var/lib/vina/feeds /var/lib/vina/plugins /var/lib/vina/cache

COPY --from=builder /build/dist/*.whl /tmp/
RUN pip install --no-cache-dir /tmp/*.whl && rm /tmp/*.whl

USER vina
WORKDIR /home/vina

ENV VINA_HOME=/var/lib/vina
ENV VINA_CACHE_DIR=/var/lib/vina/cache
ENV VINA_FEED_DIR=/var/lib/vina/feeds
ENV VINA_PLUGIN_DIR=/var/lib/vina/plugins

VOLUME ["/var/lib/vina/feeds", "/var/lib/vina/plugins", "/var/lib/vina/cache"]

ENTRYPOINT ["vina"]
CMD ["--help"]
