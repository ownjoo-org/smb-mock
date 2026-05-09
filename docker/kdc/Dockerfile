FROM alpine:3.23

RUN apk add --no-cache \
        python3 \
        krb5 \
        krb5-server \
    && mkdir -p /var/lib/krb5kdc /etc/krb5kdc /shared

COPY config.py entrypoint.py /app/
WORKDIR /app

VOLUME ["/shared"]

# 88 only — kadmind (749) stays inside the Docker network, never exposed on host
EXPOSE 88/tcp
EXPOSE 88/udp

# Healthy once the service keytab has been written (proves full init complete).
HEALTHCHECK --interval=5s --timeout=3s --start-period=90s --retries=24 \
    CMD test -f /shared/krb5.keytab

CMD ["python3", "entrypoint.py"]
