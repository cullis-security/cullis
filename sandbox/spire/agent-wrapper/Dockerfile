# Wrapper around the distroless spire-agent image so we get a shell
# (needed to read the join-token file from a shared volume at start time).
FROM ghcr.io/spiffe/spire-agent:1.9.5 AS bin
FROM alpine:3.20
COPY --from=bin /opt/spire/bin/spire-agent /usr/local/bin/spire-agent
ENTRYPOINT ["/bin/sh", "-c"]
