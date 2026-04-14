# Homebrew formula for `cullis-connector`.
#
# This file is a TEMPLATE intended to be copied into the Cullis Homebrew
# tap repository (`cullis-security/homebrew-tap`) at release time. It is
# NOT consumed directly from this monorepo — Homebrew expects formulas in
# a dedicated `homebrew-<name>` tap layout.
#
# Users install via:
#
#   brew tap cullis-security/tap
#   brew install cullis-connector
#
# Release cycle for maintainers:
#   1. Cut a `connector-vX.Y.Z` tag on the monorepo (see RELEASING.md)
#   2. GitHub Actions publishes the sdist tarball to
#      https://github.com/cullis-security/cullis/releases/download/...
#   3. Maintainer opens a PR on `cullis-security/homebrew-tap` that
#      updates `url`, `version`, and `sha256` below
#   4. Homebrew CI runs `brew test-bot`; merge on green
#
# This formula installs the connector as a *Python formula* via
# `virtualenv_install_with_resources`, which is Homebrew's recommended
# pattern for Python CLI tools. Heavy C-extension deps (`cryptography`)
# are pulled from bottled Homebrew formulas rather than compiled from
# source.

class CullisConnector < Formula
  include Language::Python::Virtualenv

  desc     "MCP server bridging local MCP clients to the Cullis agent-trust network"
  homepage "https://cullis.io"
  url      "https://github.com/cullis-security/cullis/releases/download/connector-v0.1.0/cullis_connector-0.1.0.tar.gz"
  sha256   "REPLACE_WITH_SDIST_SHA256_ON_RELEASE"
  license  "FSL-1.1-Apache-2.0"
  head     "https://github.com/cullis-security/cullis.git", branch: "main"

  depends_on "python@3.12"
  depends_on "rust" => :build        # required to build `cryptography` from sdist
  depends_on "openssl@3"

  # Python runtime dependencies. `brew update-python-resources` regenerates
  # this block on version bumps — do NOT hand-edit the resource URLs in
  # long-lived forks, regenerate them.
  resource "httpx" do
    url "https://files.pythonhosted.org/packages/source/h/httpx/httpx-0.27.0.tar.gz"
    sha256 "REPLACE_ON_RELEASE"
  end

  resource "cryptography" do
    url "https://files.pythonhosted.org/packages/source/c/cryptography/cryptography-42.0.0.tar.gz"
    sha256 "REPLACE_ON_RELEASE"
  end

  resource "mcp" do
    url "https://files.pythonhosted.org/packages/source/m/mcp/mcp-1.0.0.tar.gz"
    sha256 "REPLACE_ON_RELEASE"
  end

  resource "pyyaml" do
    url "https://files.pythonhosted.org/packages/source/p/pyyaml/pyyaml-6.0.1.tar.gz"
    sha256 "REPLACE_ON_RELEASE"
  end

  # Add further resources as required — run:
  #   brew update-python-resources cullis-connector
  # to generate the full dependency tree with correct sha256 values.

  def install
    virtualenv_install_with_resources
  end

  test do
    # `--version` exits 0 and prints the expected tag.
    assert_match version.to_s, shell_output("#{bin}/cullis-connector --version")

    # `serve` without an identity must fail fast with a clear hint,
    # not hang on stdio or crash unexpectedly.
    output = shell_output(
      "#{bin}/cullis-connector serve --config-dir #{testpath}/nonexistent 2>&1",
      2,  # expected non-zero exit code
    )
    assert_match(/no identity/i, output)
  end
end
