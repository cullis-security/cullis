ARG NGINX_BASE=nginx:1.27-alpine
FROM ${NGINX_BASE}
# Built during preparation, before private state is mounted or runtime starts.
RUN apk add --no-cache iptables setpriv
COPY entrypoint.sh /usr/local/bin/local-demo-nginx
RUN chmod 0555 /usr/local/bin/local-demo-nginx
ENTRYPOINT ["/usr/local/bin/local-demo-nginx"]
CMD ["nginx", "-g", "daemon off;"]
