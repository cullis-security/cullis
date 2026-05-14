---
title: "Disaster recovery"
description: "Backup and restore for the Cullis Mastio Enterprise bundle. Hot SQLite snapshot, encrypted tarball, full restore in ~15 min. Includes scenario walk-throughs for VM loss, ransomware, accidental wipe."
category: "Operate"
order: 6
updated: "2026-05-14"
---

# Disaster recovery

The Mastio is the trust root of your agent population: its Org CA
signs every agent certificate, and its `mcp_proxy.db` carries every
session, audit record, and user/agent enrollment. Losing it without
a backup means re-enrolling everything from scratch with a new Org
CA — every Connector, every agent, every cert thumbprint pin. With
the bundle's `backup.sh` and `restore.sh`, recovery is a 15-minute
job from any host that can read the encrypted backup file.

## What gets backed up

| Path | Contents | Why critical |
|---|---|---|
| `data/mcp_proxy.db` | SQLite: agents, sessions, audit log, users, config | Loss = full re-enrollment |
| `nginx-certs/org-ca.{crt,key}` | Org CA keypair (trust root) | Loss = every agent cert invalidated |
| `nginx-certs/mastio-server.{crt,key}` | Server cert for nginx sidecar | Loss = TLS termination broken |
| `saml-keys/` (if saml_sso) | SAML SP signing keypair | Loss = SAML metadata mismatch |
| `proxy.env` (redacted) | All operator-side config (PUBLIC_URL, plugin envs, secrets refs) | Loss = re-tuning from scratch |

What is **not** backed up:

- `CULLIS_LICENSE_KEY` JWT (REDACTED in `proxy.env` copy inside the
  tarball). The license is a contract artefact from Cullis Security;
  re-issued at restore time if missing.
- Plugin secrets in operator's external systems (Vault, AWS Secrets
  Manager, etc.) — those have their own backup strategy.
- Cloud KMS Org CA key copy (if `MCP_PROXY_KMS_BACKEND` is set to
  `vault`/`aws`/`azure`/`gcp`) — the key lives in the KMS already,
  outside the bundle. Bundle backup snapshots only the proxy's view.

## Taking a backup

From inside the bundle dir:

```bash
./backup.sh
```

Prompts for an encryption passphrase. Output:

```
backups/cullis-mastio-enterprise-backup-20260514T103025Z.tar.gz.gpg
```

The hot SQLite snapshot is consistent without stopping the running
proxy (uses `sqlite3 .backup`). Cert files are copied as-is; they
rarely change at runtime.

### Non-interactive (cron)

For scheduled backups, pre-place the passphrase in a 0400-mode file
and pass `--passphrase-file`:

```bash
./backup.sh --passphrase-file /etc/cullis/backup.pass --out /var/backups/cullis
```

Sample cron entry (daily 02:00, retain 30 days):

```cron
0 2 * * *  cd /opt/cullis-mastio-enterprise-bundle && ./backup.sh \
             --passphrase-file /etc/cullis/backup.pass \
             --out /var/backups/cullis \
           && find /var/backups/cullis -mtime +30 -name '*.tar.gz.gpg' -delete
```

### Off-host copy

The encrypted file is safe to transmit over untrusted channels. Pick
one (or several):

```bash
# rsync to a separate host
rsync -a backups/cullis-mastio-enterprise-backup-*.tar.gz.gpg \
      backup-host:/var/backups/cullis/

# S3
aws s3 cp backups/cullis-mastio-enterprise-backup-*.tar.gz.gpg \
          s3://yourorg-cullis-backups/

# USB drive
cp backups/cullis-mastio-enterprise-backup-*.tar.gz.gpg /mnt/usb/cullis/
```

**The passphrase is the only secret.** Store it in your password
manager (Bitwarden, 1Password) under a different item from the
backup itself. Both lost = data unrecoverable.

## Restoring

On a fresh host or after disaster, install the bundle as usual
(`docker login ghcr.io`, `curl ... tar xz`, `cd
cullis-mastio-enterprise-bundle/`), then:

```bash
./restore.sh /path/to/cullis-mastio-enterprise-backup-*.tar.gz.gpg
```

Prompts for the passphrase. Output:

```
✓  decrypted
✓  extracted to /tmp/...
✓  all checksums verified
✓  no stack running
✓  bind-mount contents restored
!  proxy.env preserved; backup copy written to proxy.env.restored for diff

Restore complete
```

After restore:

1. Compare `proxy.env` (your current config) with `proxy.env.restored`
   (the backup's snapshot). If you trust the backup version, adopt it:
   ```bash
   diff proxy.env proxy.env.restored
   mv proxy.env.restored proxy.env
   ```
2. The `CULLIS_LICENSE_KEY` in the restored file is `REDACTED`. Paste
   the JWT from your password manager. If the JWT was issued more than
   90 days before the backup, request a fresh one from
   `hello@cullis.io`.
3. Bring up the stack:
   ```bash
   ./deploy.sh
   ```
4. Verify post-boot:
   ```bash
   docker compose -p cullis-mastio-enterprise logs mcp-proxy | grep -E "license:|plugin loaded:"
   ```
   You should see `tier=enterprise` and the same plugin set as before.

## Scenario walk-throughs

### VM disk failure (most common)

1. Provision new VM, install Docker.
2. `docker login ghcr.io -u <user> --password-stdin` with the same PAT.
3. Download bundle, `tar xz`, `cd cullis-mastio-enterprise-bundle/`.
4. `./restore.sh /path/to/latest-backup.tar.gz.gpg` (mount the off-host
   backup volume or copy the file via scp first).
5. Edit `proxy.env`, re-paste license JWT.
6. `./deploy.sh`.

Time: ~15 minutes including DNS update if `MCP_PROXY_PROXY_PUBLIC_URL`
changes. Existing agents continue working as long as they can reach
the new IP and the Org CA cert is restored (= preserves their
thumbprint pin).

### Ransomware / host compromise

1. Quarantine the affected host (do not power it back on; preserve
   forensics).
2. Provision new VM as above.
3. Restore from the **last clean** backup (verify the timestamp pre-dates
   the suspected breach).
4. Rotate all secrets that could have leaked:
   - License JWT: request fresh one from `hello@cullis.io`
   - `MCP_PROXY_ADMIN_SECRET`, `MCP_PROXY_DASHBOARD_SIGNING_KEY` in
     `proxy.env` — regenerate with `openssl rand -hex 32`
   - Cloud creds (`AWS_ACCESS_KEY_ID`, Azure SP, etc.) — rotate at IdP
   - Any Vault tokens — revoke + re-issue
5. Force agent cert re-issuance for any agent that could have had its
   private key exposed (via dashboard `/proxy/agents/<id>/rotate-cert`).
6. Audit log review on the restored DB to identify the breach window.

### Accidental wipe (`rm -rf data/` on the wrong host)

1. Stop the stack: `./deploy.sh --down`.
2. Find the most recent backup: `ls -lt backups/ | head -3`.
3. `./restore.sh <latest> --force` (the `--force` flag is required
   because the bundle dir is not empty).
4. `./deploy.sh`.

Time: ~5 minutes since you're not provisioning a new host.

### Org CA key rotation after suspected compromise

The Org CA key is the most sensitive material in the deploy. If you
suspect it leaked:

1. Take a backup first (audit trail).
2. Stop the stack.
3. **Rotate the Org CA**: this is intrusive. Every agent cert needs
   re-issuance under the new CA, every Connector needs to re-enroll.
   See [rotate-keys](./rotate-keys) for the full procedure.
4. Distribute the new CA cert to all agents via their next
   enrollment.

Backup helps here by giving you a known-good baseline to roll forward
from, but the rotation itself is independent.

## Compliance mapping

The backup pattern aligns with these common controls:

| Control | What |
|---|---|
| SOC 2 CC9.2 (data backup) | Encrypted off-host backup with documented frequency |
| ISO 27001 A.8.13 (information backup) | Same |
| DORA Art. 12 (ICT business continuity) | RPO + RTO defined (24h / 15min) |
| EU AI Act Art. 12 (record-keeping) | Audit log preserved in `mcp_proxy.db` |
| ISO 22301 (BCMS) | DR runbook documented + tested |

Recommended cadence:

- **Backup**: daily for production, weekly for staging
- **Off-host copy**: every backup (no point keeping it on the same disk)
- **Restore drill**: quarterly on a non-prod host. Verify the
  procedure still works end-to-end. Document any drift in the runbook.
