# NixOS-test entry point for the Cullis cross-org network demo.
#
# Each scenario is a ``nixosTest`` derivation that boots one or more
# VMs running the live Cullis stack (broker + proxy + frontdesk +
# Cullis Chat + MCP echo) on isolated kernels and exercises the wire
# protocol end-to-end via a Python testScript.
#
# Build a scenario:
#
#     nix-build tests/integration/cullis_network -A tier1-roma
#
# Drop into the interactive driver for manual poking (boot the VMs,
# get a shell, run individual commands):
#
#     $(nix-build tests/integration/cullis_network -A tier1-roma.driverInteractive)/bin/nixos-test-driver
#
# Caller supplies ``pkgs`` so this file does not pin a channel itself —
# CI, the dev shell, and ``nix run`` wrappers all decide their own
# nixpkgs revision. Falls back to ``<nixpkgs>`` for ad-hoc local runs.
{
  pkgs ? import <nixpkgs> { },
  cullisSrc ? ../../..,
}:

let
  lib = pkgs.lib;
  callTest = path: import path { inherit pkgs cullisSrc lib; };
in
{
  tier1-roma = callTest ./tier1-roma.nix;

  # Tier 2 (4 VMs cross-org Roma + San Francisco + Tokyo + Court) lands
  # in a follow-up commit — the scaffold here intentionally ships the
  # minimal viable demo first so the CI cost stays bounded while we
  # validate the system around it.
  # tier2-cross-org = callTest ./tier2-cross-org.nix;
}
