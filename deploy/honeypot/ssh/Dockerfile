FROM alpine:3.24

ARG HONEYPOT_SSH_PASSWORD=highwall-decoy-only

RUN apk add --no-cache openssh-server shadow \
    && echo "root:${HONEYPOT_SSH_PASSWORD}" | chpasswd \
    && sed -i 's#^root:x:0:0:root:/root:#root:x:0:0:root:/tmp:#' /etc/passwd \
    && mkdir -p /run/sshd

COPY sshd_config /etc/ssh/sshd_config
COPY entrypoint.sh /usr/local/bin/honeypot-entrypoint

RUN chmod 0755 /usr/local/bin/honeypot-entrypoint

EXPOSE 2222

ENTRYPOINT ["/usr/local/bin/honeypot-entrypoint"]
