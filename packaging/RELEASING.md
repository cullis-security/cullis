# Releasing `cullis-connector`

Step-by-step checklist for cutting a new connector release. The whole
flow is gated on pushing a `connector-vX.Y.Z` tag; the GitHub Actions
workflow (`.github/workflows/release-connector.yml`) handles the rest.

---

## 0. Prerequisites (one-off)

- Write access to `cullis-security/cullis`.
- `PYPI_TOKEN` secret configured on the repo (needed for PyPI upload;
  the workflow no-ops its `publish-pypi` job until this is present).
- `ghcr.io` write via the built-in `GITHUB_TOKEN` (already works; no
  extra setup needed).
- Clone of `cullis-security/homebrew-tap` (only required when you
  want to bump the Homebrew formula — see step 6).

---

## 1. Bump the version

Bump both files together. They must stay in sync:

- `packaging/pypi/pyproject.toml` → `[project] version = "X.Y.Z"`
- `cullis_connector/__init__.py` → `__version__ = "X.Y.Z"`

Quick sanity check:

```bash
grep -E '^(version|__version__)' \
  packaging/pypi/pyproject.toml cullis_connector/__init__.py
```

The two lines must show the same `X.Y.Z`.

---

## 2. Update the changelog

Add a new section to `CHANGELOG.md` at the top, below the title:

```markdown
## [vX.Y.Z] — YYYY-MM-DD

### Added
- ...

### Changed
- ...

### Fixed
- ...

### Security
- ...

[vX.Y.Z]: https://github.com/cullis-security/cullis/releases/tag/connector-vX.Y.Z
```

Keep entries short and user-oriented. The release workflow extracts
this section verbatim and uses it as the GitHub Release body.

---

## 3. Commit and open a release PR

```bash
git checkout -b release/connector-vX.Y.Z
git add packaging/pypi/pyproject.toml cullis_connector/__init__.py CHANGELOG.md
git commit -sm "release(connector): vX.Y.Z"
git push -u origin release/connector-vX.Y.Z
gh pr create --title "release(connector): vX.Y.Z" --body "See CHANGELOG"
```

Wait for CI green + review + merge into `main`.

---

## 4. Tag and push

After the release PR lands on `main`:

```bash
git checkout main
git pull --ff-only
git tag -a connector-vX.Y.Z -m "cullis-connector vX.Y.Z"
git push origin connector-vX.Y.Z
```

The tag push triggers `release-connector.yml`. Watch it with:

```bash
gh run watch --exit-status
```

---

## 5. Verify artefacts

Once the workflow is green:

- **PyPI** (skip until `PYPI_TOKEN` is provisioned and the
  `publish-pypi` job guard is flipped):
  ```bash
  pip install --upgrade cullis-connector
  cullis-connector --version    # → cullis-connector X.Y.Z
  ```

- **Docker**:
  ```bash
  docker pull ghcr.io/cullis-security/cullis-connector:vX.Y.Z
  docker run --rm ghcr.io/cullis-security/cullis-connector:vX.Y.Z --version
  ```

- **GitHub Release**: visit
  <https://github.com/cullis-security/cullis/releases/tag/connector-vX.Y.Z>
  and confirm the wheel, sdist, and Linux / macOS binaries are
  attached, and the release notes render the changelog correctly.

---

## 6. Bump the Homebrew tap (optional)

Only needed on releases we want to surface via `brew`. Takes ~5 min.

```bash
cd ../homebrew-tap
git checkout -b bump/cullis-connector-vX.Y.Z

# Edit Formula/cullis-connector.rb
#   - url:     point at the new sdist on GitHub Releases
#   - version: X.Y.Z
#   - sha256:  shasum -a 256 cullis_connector-X.Y.Z.tar.gz
brew update-python-resources cullis-connector   # regenerates resource hashes
brew install --build-from-source ./Formula/cullis-connector.rb
brew test cullis-connector
brew audit --strict cullis-connector

git commit -asm "cullis-connector vX.Y.Z"
git push -u origin bump/cullis-connector-vX.Y.Z
gh pr create --title "cullis-connector vX.Y.Z" --body "Automated bump"
```

Merge once `brew test-bot` is green.

---

## 7. Announce

- Update the landing page release banner if the release is notable.
- Post to the project X/LinkedIn accounts (tone guidelines in
  `feedback_marketing_tone.md`).
- Notify any pilot customers directly about breaking changes or
  security fixes.

---

## Rollback

If a release turns out broken:

1. **Yank from PyPI** — `pypi yank cullis-connector X.Y.Z --reason "..."`.
2. **Delete the ghcr.io tag** (keep `latest` pinned at the previous
   good version).
3. **Delete the GitHub Release** (keeps the tag; that's fine).
4. **Do NOT delete the git tag** — CI assumes tags are immutable;
   instead, cut a `X.Y.Z+1` patch release with the fix.
