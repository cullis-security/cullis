#!/bin/sh
# Rules apply only to this container's network namespace, never to the host.
set -eu

# Resolve the one Docker service before closing DNS. Refresh our hosts entry on
# every start, including restarts after the upstream container was replaced.
awk '!/# cullis-local-upstream$/' /etc/hosts > /tmp/local-demo-hosts
cat /tmp/local-demo-hosts > /etc/hosts
upstream=$(getent hosts mcp-proxy | awk '$1 ~ /^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$/ {print $1; exit}')
test -n "$upstream"
printf '%s mcp-proxy # cullis-local-upstream\n' "$upstream" >> /etc/hosts

# Default-deny before adding exceptions; nginx is not listening yet. Do not
# allow UDP/DNS, even to Docker's embedded resolver (which can forward outside).
iptables -P OUTPUT DROP
iptables -P FORWARD DROP
iptables -F OUTPUT
iptables -A OUTPUT -p tcp -m conntrack --ctstate ESTABLISHED -j ACCEPT
iptables -A OUTPUT -p tcp -d "$upstream" --dport 9100 -j ACCEPT
iptables -A OUTPUT -p tcp -d 127.0.0.1 --dport 9443 -j ACCEPT
ip6tables -P OUTPUT DROP
ip6tables -P FORWARD DROP
ip6tables -F OUTPUT
ip6tables -A OUTPUT -p tcp -m conntrack --ctstate ESTABLISHED -j ACCEPT

# The startup process needs NET_ADMIN; nginx and its children must not retain
# it or regain it. Also remove raw sockets from the capability bounding set.
exec setpriv --bounding-set=-net_admin,-net_raw --inh-caps=-all \
    --ambient-caps=-all --no-new-privs /docker-entrypoint.sh "$@"
