# Local CAPD Apache header-check approval

Apache HTTP header verification has its own operation, `CAPD_HTTP_HEADER_VERIFY`.
It is disabled unless explicitly included in `ASIP_DEFAULT_SCAN_OPERATIONS`.
It does not enable `HTTP_TLS_OBSERVATION` or `ADHOC_CHECK` and it does not grant
permission for CVE payloads. Live transport remains disabled in this release.

## Trust boundary

The source includes a host approval helper at `capd_local_approval.py` and its
small shared contract module at `capd_approval_contract.py`. Install both
root-owned in `/usr/local/libexec/`, placing the helper at
`/usr/local/libexec/asip-capd-approve` and the contract module beside it. The
helper must not be writable by group or others. The helper refuses to issue approvals unless it
runs with effective UID 0, its real UID is a non-root user in the
`asip-capd-operator` OS group, the installed path and all parent directories
are root-protected, and the Ed25519 private key at
`/etc/asip/capd-approval-ed25519.pem` is root-owned and mode 0400 or 0600.
Identity comes from the kernel real UID and the host group database; no
`SUDO_UID`, username argument, environment variable, client header, or
container-root identity is trusted.

The backend receives only the public key, mounted read-only at
`/run/secrets/capd-approval-ed25519.pub`. The host private key must never be
copied into the backend image or container. The CLI verifies a signed token
bound to one Apache check revision, one successful source scan, one asset ID,
one stored HTTP origin, method `GET`, a one-request budget, and a 120-second
maximum lifetime. The host helper displays those exact values and requires an
interactive `APPROVE <asset-id>` confirmation. A fresh database policy check
still gates the target after signature verification.

## Host installation prerequisite

These are operator-run installation steps for a later approved release; they
are intentionally not executed by this source-only milestone:

1. Create the dedicated `asip-capd-operator` group and add only approved local
   operators (for example, `groupadd --system asip-capd-operator` followed by
   `usermod -aG asip-capd-operator <approved-user>`). Do not add the
   application/container account.
2. Generate an Ed25519 key pair on the trusted host. Keep the private key
   root-owned under `/etc/asip/` with mode 0400; install only the public key
   into the backend container through a read-only bind mount at the path above.
   For example:

   ```sh
   install -d -o root -g root -m 0755 /etc/asip
   openssl genpkey -algorithm ED25519 -out /etc/asip/capd-approval-ed25519.pem
   chown root:root /etc/asip/capd-approval-ed25519.pem
   chmod 0400 /etc/asip/capd-approval-ed25519.pem
   openssl pkey -in /etc/asip/capd-approval-ed25519.pem -pubout \
     -out /etc/asip/capd-approval-ed25519.pub
   chown root:root /etc/asip/capd-approval-ed25519.pub
   chmod 0444 /etc/asip/capd-approval-ed25519.pub
   ```

   The host helper also requires Python `cryptography` to be installed. Bind
   mount the public file read-only as
   `/run/secrets/capd-approval-ed25519.pub` in the backend service.
3. Install the helper as
   `install -o root -g root -m 0755 backend/capd_local_approval.py /usr/local/libexec/asip-capd-approve`
   and the contract module as
   `install -o root -g root -m 0644 backend/capd_approval_contract.py /usr/local/libexec/capd_approval_contract.py`.
   Keep parent directories root-owned and non-writable by group or others.
4. Add a narrowly reviewed sudoers rule using `visudo -f
   /etc/sudoers.d/asip-capd-operator`, for example:
   `%asip-capd-operator ALL=(root) NOPASSWD: /usr/local/libexec/asip-capd-approve`.
   The helper validates every argument, checks the real UID/group, and
   interactively confirms the one target before signing.
5. Apply migration `016_add_capd_http_header_verify_operation.sql` through the
   approved optional migration process before storing operation-specific exclusions.
   It extends only the existing operation constraint and does not alter
   existing approvals or enable the operation.
6. During a separately approved release, configure the backend operation
   allowlist to include `CAPD_HTTP_HEADER_VERIFY`. This is an operation policy
   gate, not operator identity or target approval.

## Dry-run workflow

1. Preview Apache evidence with `capd targets --product apache --scan-id N`.
2. Select one product-matched `domain_id`, then run
   `capd apache-version --dry-run --scan-id N --asset-id ID`. The output's
   `approval_request` contains the run ID, asset, and exact stored origin.
3. Invoke the installed host helper with those displayed values. Pipe its
   signed JSON output to
   `capd apache-version --dry-run --asset-id ID --approval-stdin --scan-id N`.
4. The CLI verifies the signature, checks the operation policy, reselects the
   asset from the successful inventory scan, and freshly rechecks current
   Known/Shadow class, ownership, scannability, trusted boundary, Apache
   evidence, exclusions, endpoint, and approval lifetime. The result is an
   authorization preview only: zero network requests, zero writes, and live
   execution remains disabled.

For example, the helper is run with the values printed in `approval_request`:

```sh
sudo /usr/local/libexec/asip-capd-approve \
  --run-id RUN_ID --scan-id SCAN_ID --asset-id ASSET_ID \
  --domain HOST --origin 'https://HOST/' |
  docker compose exec -T backend python3 /app/capd_cli.py apache-version \
    --dry-run --scan-id SCAN_ID --asset-id ASSET_ID --approval-stdin
```

When a live path is separately approved, it must consume the run ID through
the existing unique CAPD run persistence before any I/O, revalidate immediately
before connecting, enforce the signed one-request budget, and refuse redirects.
An approval token by itself is never evidence that a check was executed or a
vulnerability was found.
