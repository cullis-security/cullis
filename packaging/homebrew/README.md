# Homebrew tap template

This directory holds the source-of-truth Homebrew formula for
`cullis-connector`. The tap itself lives in a separate repo
(`cullis-security/homebrew-tap`) — Homebrew requires each tap to live at
`github.com/<org>/homebrew-<name>`.

## Release flow

Each time a `connector-vX.Y.Z` tag is pushed on the monorepo:

1. The release workflow uploads the sdist to GitHub Releases.
2. A maintainer bumps `version`, `url`, `sha256`, and Python resource
   hashes in the tap repo copy of `cullis-connector.rb`.
3. `brew update-python-resources cullis-connector` regenerates the
   `resource` blocks.
4. Open a PR on the tap repo, wait for `brew test-bot` to pass, merge.

## Local testing before tap PR

```bash
# From the tap repo working tree:
brew install --build-from-source ./cullis-connector.rb
brew test cullis-connector
brew audit --strict cullis-connector
```

## First-time tap setup (one-off, not required on every release)

```bash
gh repo create cullis-security/homebrew-tap --public \
  --description "Homebrew tap for Cullis tooling"

git clone https://github.com/cullis-security/homebrew-tap
cd homebrew-tap
mkdir Formula
cp <monorepo>/packaging/homebrew/cullis-connector.rb Formula/
git add . && git commit -sm "Add cullis-connector formula"
git push
```

After that, end users tap with:

```bash
brew tap cullis-security/tap
brew install cullis-connector
```
