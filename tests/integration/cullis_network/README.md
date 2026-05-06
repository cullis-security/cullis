# Cullis network — nixosTest

Integration tests that boot real NixOS VMs running the full Cullis
stack and exercise it end-to-end. Closer to production than the
`docker compose` sandbox: every "city" lives on its own kernel,
network namespace, hostname, TLS chain, and audit DB. Cross-org
traffic between them traverses a virtual L2 the test framework
provisions, so `tcpdump`-able and partition-able by design.

## Why this exists

The compose sandbox shares a kernel and a Docker bridge — fine for
quick iteration, weak for the "infrastructure cross-org" pitch.
Reviewers (CISOs, design partners) discount a demo where every org
is `localhost`. nixosTest gives us:

- isolated kernels + network namespaces (no shared sysctls, no
  shared `/etc/hosts`)
- per-VM PKI: Roma's Org CA can't impersonate San Francisco's even
  if compromised
- realistic failure modes: kill a VM, partition the link between
  two cities, drop packets on a single firewall, see the system
  degrade exactly like prod
- hermetic CI: every run rebuilds from the same Nix store, no
  drift between developer laptop and CI runner

## Layout

| File | Scenario |
|------|----------|
| `default.nix` | Entry point — exposes named scenarios |
| `tier1-roma.nix` | 1 VM (`roma`). Intra-org Frontdesk → MCP. The minimal viable demo |
| `tier2-cross-org.nix` | 4 VMs (`roma`, `sanfrancisco`, `tokyo`, `court`). Cross-continent A2A + Court audit dual-write |
| `lib/cullis-mastio.nix` | Reusable NixOS module that drops broker + proxy + nginx onto a host |
| `lib/cullis-frontdesk.nix` | Reusable module for Frontdesk shared-mode + Cullis Chat |

## Running

Each scenario builds and runs as an attribute of `default.nix`:

```bash
# Tier 1 — single VM, intra-org Frontdesk demo
nix-build tests/integration/cullis_network -A tier1-roma

# Interactive driver (drop into a Python REPL with the VMs running):
$(nix-build tests/integration/cullis_network -A tier1-roma.driverInteractive)/bin/nixos-test-driver
```

The interactive driver is the same flow the test harness uses:
inside the REPL `roma.start()` boots the VM, `roma.shell_interact()`
gives you a shell, `roma.succeed("curl http://localhost:8080/...")`
exercises the live flow.

## Geography

The cross-org scenario ships three Mastios in three timezones to
mirror the cross-continent pitch:

- **Roma** (`mastio.roma.cullis.test`, CET) — EU GDPR / eIDAS, the
  "European bank" archetype
- **San Francisco** (`mastio.sf.cullis.test`, PST) — US fintech /
  SOC2, the "Silicon Valley counterparty"
- **Tokyo** (`mastio.tokyo.cullis.test`, JST) — APPI / Japanese
  enterprise, the "Asian supplier"
- **Court** (`court.cullis.test`, neutral) — the federated trust
  fabric all three publish to

A Roma agent can A2A-message a Tokyo agent without either Mastio
trusting the other directly: Court is the third witness that
signs the cross-org binding and ships the audit dual-write.

## Status

- [x] **Tier 1 (roma)** — single-VM intra-org. Boots broker + proxy
      + Frontdesk shared-mode + Cullis Chat + MCP postgres echo.
      Test runs the daniele@user → MCP query → audit chain
      validation we exercised live on the compose sandbox in #445.
- [ ] **Tier 2 (cross-org)** — 4 VMs, A2A oneshot Roma→Tokyo
      through Court, federation publisher, cross-org audit
      dual-write, partition test (kill Court, both Mastios
      degrade gracefully).

## Notes

- `lib/cullis-mastio.nix` runs Cullis as **systemd units**, not
  Docker. It picks the source tree up via a shared dir and
  installs the wheel + the `cullis_sdk` egg into a per-VM venv at
  build time. The compose sandbox uses Docker; nixosTest is the
  "this is how prod looks" path.
- TLS material is generated per-VM at first boot. Each VM's Org
  CA private key is a virtio-rng-derived ephemeral keypair, never
  committed.
- The `default.nix` does **not** import `<nixpkgs>` itself; it
  takes `pkgs` as a parameter so callers (CI, developer shells,
  the `nix run` wrapper) can pin a specific channel or flake input.
