# ShadowRecon v0.1.0 Internal-Alpha Release Checklist

- [ ] `.env` created from `.env.example`, permissions restricted, and no placeholders remain.
- [ ] All credentials that were ever exposed or committed have been revoked and rotated.
- [ ] `docker compose config --quiet` succeeds without unset-variable warnings.
- [ ] Fresh database bootstrap or the existing database's migrations have been verified.
- [ ] Approved seed roots, known inventory, and sensitive-port policy are configured.
- [ ] Services build and start; `docker compose ps` reports a healthy database and running application services.
- [ ] Dashboard is reachable on port 3555.
- [ ] Backend root is reachable on port 8555.
- [ ] MCP summary is reachable on port 8666 when MCP is enabled.
- [ ] One representative, explicitly approved orchestration run completes successfully.
- [ ] The new `SUCCEEDED` scan is shown as authoritative; newer failed/running scans are not.
- [ ] Overview, Assets, Risk, Shadow, Brand, Changes, Scans, Investigation, and Ownership Review load.
- [ ] Candidate/External assets show no organizational canonical risk.
- [ ] Ownership confirmation does not grant T2 authorization.
- [ ] Review Indicators remain evidence for review, not automatic findings/vulnerabilities.
- [ ] A fresh custom-format database backup is created, listed successfully, checksummed, and stored safely.
- [ ] Restore is tested against a disposable empty database and the test database is removed.
- [ ] Backend tests pass.
- [ ] Frontend tests and production build pass.
- [ ] Current frontend dependency advisories have been reviewed and explicitly accepted for the internal-alpha boundary.
- [ ] No secrets, `.env`, database archives, logs, or runtime artifacts are staged.
- [ ] Only expected runtime files (currently `backend/data/final_output.csv`) remain dirty.
- [ ] Commit is reviewed and ready for the `v0.1.0` tag.

Do not create or push the tag until every required manual smoke item is complete and approved.
