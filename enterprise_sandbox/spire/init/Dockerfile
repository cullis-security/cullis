# Tiny image to run `spire-server token generate` + `entry create` against
# a sibling spire-server container. The official spire-server image is
# distroless — no /bin/sh — so we copy the CLI into an alpine layer that
# has a shell + awk.
FROM ghcr.io/spiffe/spire-server:1.9.5 AS bin
FROM alpine:3.20
COPY --from=bin /opt/spire/bin/spire-server /usr/local/bin/spire-server
RUN apk add --no-cache gawk
ENTRYPOINT ["/bin/sh", "-c"]
