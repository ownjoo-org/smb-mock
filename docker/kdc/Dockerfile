FROM cgr.dev/chainguard/wolfi-base

RUN apk add --no-cache \
        python-3.12 \
        krb5 \
        krb5-server \
    && mkdir -p /var/lib/krb5kdc /etc/krb5kdc /shared

COPY config.py entrypoint.py /app/
WORKDIR /app

# 88  — KDC ticket service
# 8088 — keytab HTTP API (GET /keytab, GET /healthz)
# 749 (kadmind) intentionally NOT exposed — stays inside Docker network only
EXPOSE 88/tcp
EXPOSE 88/udp
EXPOSE 8088/tcp

# Healthy once the HTTP server responds — proves keytab is written and served.
HEALTHCHECK --interval=5s --timeout=3s --start-period=90s --retries=24 \
    CMD wget -qO- http://localhost:8088/healthz || exit 1

CMD ["python3.12", "entrypoint.py"]
