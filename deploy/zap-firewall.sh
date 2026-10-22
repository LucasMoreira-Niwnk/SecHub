#!/bin/sh
set -eu
# This bridge is exclusively for disposable ZAP containers.
iptables -w 5 -N SECHUB_ZAP 2>/dev/null || true
iptables -w 5 -I SECHUB_ZAP 1 -j DROP
iptables -w 5 -C DOCKER-USER -i sechubzap0 -j SECHUB_ZAP 2>/dev/null || iptables -w 5 -I DOCKER-USER 1 -i sechubzap0 -j SECHUB_ZAP
# Block access to every service on the Docker host, including LAN addresses.
iptables -w 5 -C INPUT -i sechubzap0 -j DROP 2>/dev/null || iptables -w 5 -I INPUT 1 -i sechubzap0 -j DROP
