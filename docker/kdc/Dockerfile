FROM cgr.dev/chainguard/wolfi-base

RUN apk add --no-cache \
        python-3.12 \
        krb5 \
        krb5-server \
    && mkdir -p /var/lib/krb5kdc /etc/krb5kdc /shared \
    && find / -perm /6000 -type f -exec chmod a-s {} \; 2>/dev/null || true

COPY config.py entrypoint.py /app/
WORKDIR /app

# 88  — KDC ticket service
# 8088 — keytab HTTP API (GET /keytab, GET /healthz)
# 749 (kadmind) intentionally NOT exposed — stays inside Docker network only
EXPOSE 88/tcp
EXPOSE 88/udp
EXPOSE 8088/tcp

# Healthy once krb5kdc is accepting connections on port 88.
# The keytab is written to /shared BEFORE os.execvp(krb5kdc) is called, so
# port-88 reachability implies the keytab is already on the shared volume.
# (The prior /healthz approach broke because os.execvp replaces the Python
# process, killing the HTTP-server daemon thread.)
HEALTHCHECK --interval=5s --timeout=4s --start-period=45s --retries=15 \
    CMD python3.12 -c "import socket; socket.create_connection(('localhost',88),3).close()" || exit 1

CMD ["python3.12", "entrypoint.py"]
