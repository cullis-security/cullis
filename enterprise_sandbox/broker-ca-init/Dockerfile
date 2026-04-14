FROM alpine:3.20
RUN apk add --no-cache openssl bash
COPY generate.sh /usr/local/bin/generate.sh
RUN chmod +x /usr/local/bin/generate.sh
ENTRYPOINT ["/usr/local/bin/generate.sh"]
