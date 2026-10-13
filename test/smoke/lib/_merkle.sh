#!/usr/bin/env bash
# Scenario 91 GETs may be shed before auth while the preceding burst drains.
# Source _common.sh first. Preserve the expected status, including 403/404.
merkle_get() (
    set -euo pipefail
    local path="$1" expected="$2" secret="$3"
    local deadline=$(( SECONDS + 30 )) remaining status body retry_after error
    local response_dir
    response_dir="$(mktemp -d)"
    trap 'rm -rf -- "$response_dir"' EXIT

    while true; do
        remaining=$(( deadline - SECONDS ))
        (( remaining > 0 )) || die "GET ${path}: circuit breaker did not recover within 30s"
        status="$(curl -sk --request GET --max-time "$remaining" \
            --header "X-Admin-Secret: ${secret}" \
            --dump-header "$response_dir/headers" --output "$response_dir/body" \
            --write-out '%{http_code}' "${NGINX_URL}${path}")" \
            || die "GET ${path}: transport failure"
        body="$(cat "$response_dir/body")"
        if [[ "$status" == "$expected" ]]; then
            printf '%s' "$body"
            return 0
        fi
        [[ "$status" == "503" ]] \
            || die "GET ${path}: HTTP ${status}, expected ${expected}"
        error="$(json_get "$body" error)"
        [[ "$error" == "db_latency_circuit_breaker_open" ]] \
            || die "GET ${path}: unrelated HTTP 503"
        # This middleware sends delta-seconds. Reject absent, malformed or
        # excessive values rather than retrying sooner than Retry-After.
        retry_after="$(awk 'tolower($1) == "retry-after:" {
            sub(/^[^:]*:[ \t]*/, ""); sub(/[ \t\r]*$/, ""); print
        }' \
            "$response_dir/headers")"
        [[ "$retry_after" =~ ^[1-9][0-9]{0,8}$ ]] \
            || die "GET ${path}: invalid circuit breaker Retry-After"
        remaining=$(( deadline - SECONDS ))
        (( retry_after < remaining )) \
            || die "GET ${path}: Retry-After exceeds remaining 30s recovery budget"
        log_info "GET ${path}: circuit breaker active; retrying in ${retry_after}s"
        sleep "$retry_after"
    done
)
