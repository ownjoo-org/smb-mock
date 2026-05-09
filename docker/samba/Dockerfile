FROM alpine:3.23

RUN apk add --no-cache \
        python3 \
        samba \
        samba-common-tools \
        krb5 \
    && mkdir -p /etc/samba /var/log/samba /run/samba /smb-data /shared

COPY config.py entrypoint.py /app/
WORKDIR /app

VOLUME ["/smb-data"]

EXPOSE 445/tcp

CMD ["python3", "entrypoint.py"]
