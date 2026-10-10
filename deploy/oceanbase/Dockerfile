FROM docker.io/oceanbase/oceanbase-ce@sha256:eaa2c3b3513fa21e4a658f197c1deb93c9d6b6eb742cfa5ef0f085f82b9cec54
ARG TARGETARCH
ARG SOURCE_COMMIT
USER root
RUN case "$TARGETARCH" in \
      amd64) pyarch=x86_64; pysha=f98121eb1fb2b05a25c1f3d2fe7cf08c3a2468c350785df3d84c2516e7280d3f ;; \
      arm64) pyarch=aarch64; pysha=05d9207e41c36fbc2d80a51d9bd5d574ed3eb1c620ead49e7fcd57cc2b64edfd ;; \
      *) exit 1 ;; \
    esac \
    && curl --fail --location --connect-timeout 30 --max-time 600 --proto '=https' "https://github.com/astral-sh/python-build-standalone/releases/download/20251007/cpython-3.12.11%2B20251007-${pyarch}-unknown-linux-gnu-install_only_stripped.tar.gz" -o /tmp/python.tar.gz \
    && echo "$pysha  /tmp/python.tar.gz" | sha256sum -c - \
    && tar -xzf /tmp/python.tar.gz -C /opt \
    && rm /tmp/python.tar.gz
ENV PATH="/opt/python/bin:${PATH}"
ENV SSL_CERT_FILE="/etc/pki/tls/certs/ca-bundle.crt"
ENV LD_LIBRARY_PATH="/home/admin/oceanbase/lib:/home/admin/oceanbase/lib64"
COPY deploy/oceanbase /opt/moltis-oceanbase
RUN chmod -R a+rX /opt/moltis-oceanbase \
    && python3 /opt/moltis-oceanbase/install-image.py "$TARGETARCH" \
    && groupadd -g 10001 oceanbase-runtime \
    && useradd -u 10001 -g 10001 -M -d /var/lib/oceanbase oceanbase-runtime \
    && mkdir -p /var/lib/oceanbase /run/public-trust /run/server-private \
    && chown 10001:10001 /var/lib/oceanbase
LABEL org.opencontainers.image.title="Moltis OceanBase CE 5.0.1.0" \
      org.opencontainers.image.revision=$SOURCE_COMMIT \
      org.opencontainers.image.licenses="Apache-2.0" \
      org.moltis.oceanbase.source="071f4d9c82841d3ecb2d0004ef9213766308b714"
WORKDIR /var/lib/oceanbase
EXPOSE 2881
HEALTHCHECK --interval=10s --timeout=5s --start-period=240s --retries=30 CMD test -f /run/oceanbase-ready
ENTRYPOINT ["python3", "/opt/moltis-oceanbase/entry.py"]
