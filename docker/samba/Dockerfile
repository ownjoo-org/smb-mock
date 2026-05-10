# hadolint ignore=DL3006
FROM cgr.dev/chainguard/wolfi-base

# hadolint ignore=DL3018,SC2015
RUN apk add --no-cache \
        python-3.12 \
        samba \
        samba-server \
        samba-common-tools \
        krb5 \
    && mkdir -p /etc/samba /var/log/samba /run/samba /smb-data /shared \
    && find / -perm /6000 -type f -exec chmod a-s {} \; 2>/dev/null || true

COPY config.py entrypoint.py /app/
WORKDIR /app

VOLUME ["/smb-data"]

EXPOSE 445/tcp

CMD ["python3.12", "entrypoint.py"]
