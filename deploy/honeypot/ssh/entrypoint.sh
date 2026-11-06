#!/bin/sh
set -eu

mkdir -p /run/sshd
chmod 0755 /run/sshd

if [ ! -f /run/sshd/ssh_host_ed25519_key ]; then
    ssh-keygen -q -t ed25519 -N "" -f /run/sshd/ssh_host_ed25519_key
fi
if [ ! -f /run/sshd/ssh_host_rsa_key ]; then
    ssh-keygen -q -t rsa -b 3072 -N "" -f /run/sshd/ssh_host_rsa_key
fi

exec /usr/sbin/sshd -D -e -f /etc/ssh/sshd_config
