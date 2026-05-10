FROM cgr.dev/chainguard/wolfi-base

RUN apk add --no-cache \
        python-3.12 \
        samba \
        samba-common-tools \
        krb5 \
    && mkdir -p /etc/samba /var/log/samba /run/samba /smb-data /shared

COPY config.py entrypoint.py /app/
WORKDIR /app

VOLUME ["/smb-data"]

EXPOSE 445/tcp

CMD ["python3.12", "entrypoint.py"]
