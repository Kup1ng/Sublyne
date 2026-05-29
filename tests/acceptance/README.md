# Acceptance tests — PRD §11

The shell scripts in this directory automate the PRD §11 acceptance
criteria that don't require human eyes on a panel. Each script is
self-contained and prints PASS/FAIL on the last line.

| # | PRD §11 criterion | Automated by | Notes |
|---|-------------------|--------------|-------|
| 1 | Drop-in install reaches working panel < 30 s | [`01_install.sh`](./01_install.sh) | Runs on a clean Ubuntu 22.04/24.04 VM. Needs root. |
| 2 | Real WG config + matching tunnel pair + ≥1 transport E2E | MANUAL ([`MANUAL.md`](./MANUAL.md)) | Needs two real VPS hosts. |
| 3 | All four transports verified | MANUAL | UDP / TCP-SYN / ICMP / ICMPv6. ICMP may be path-filtered on the real Iran link. |
| 4 | Bandwidth meter accurate to ±5 % vs iperf3 | MANUAL | Compare `/api/metrics/live` bytes_per_sec with iperf3 -u client output. |
| 5 | 1000+ sessions + 500 Mbps + panel < 500 ms + CPU < 80 % | BLOCKED ON PERF PASS | Current single-stream cap is ~50 Mbit/s; numbers will be re-validated after the separate performance rework lands. |
| 6 | Brute-force lockout blocks after 5 failures | [`06_brute_force.sh`](./06_brute_force.sh) | Hits `/api/login` from one IP and asserts the sixth request gets a 429. |
| 7 | Backup → wipe → restore preserves the four sticky values | [`07_backup_restore.sh`](./07_backup_restore.sh) | Runs against a live service; uses the existing admin cookie. |
| 8 | Stop / Delete frees the listener immediately | [`08_stop_delete.sh`](./08_stop_delete.sh) | Asserts `ss -lunp` shows the port gone within 2 s. |
| 9 | Full CI workflow passes on a representative PR | The Phase 15 PR itself | Verified by GitHub Actions. |
| 10 | Release workflow produces both artifacts | MANUAL (`gh release view`) | Verified at every tag push. |
| 11 | README documents all required sections | MANUAL | Reviewer scans the README against PRD §11.11. |
| 12 | `.claude/` + `IMPLEMENTATION_ROADMAP.md` complete | MANUAL | Verified by `ls .claude/skills/` and reading the roadmap. |

## How to run

The automated scripts assume the panel is reachable on `localhost`
(the host running them is the same one running `sublyne`). They read
the panel port and web path from `/etc/sublyne/config.toml`.

```sh
# Run them one at a time so a failure on an earlier one doesn't
# mask later failures:
sudo ./tests/acceptance/01_install.sh
sudo ./tests/acceptance/06_brute_force.sh
sudo ./tests/acceptance/07_backup_restore.sh
sudo ./tests/acceptance/08_stop_delete.sh
```

For the manual criteria, follow the checklist in
[`MANUAL.md`](./MANUAL.md) and capture screenshots / `iperf3` output
in the PR description.
