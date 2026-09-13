# SCA Tooling

Lets you run [Wazuh](https://github.com/wazuh/wazuh) Security Configuration Assessment (SCA) policies (CIS YAML) locally,
using the same `wazuh-regex` engine Wazuh uses in production. Useful for quick local validation,
fast client checks, and iterating on policy files while you write them.

```bash
./sca.sh -pdc                       # run the full policy, per-check output
./sca.sh -soc -pdc -i 18500         # run a single check by ID
./sca.sh -f ./cis_ubuntu22-04.yml   # run a different policy file
./sca.sh -h                         # show help
```

## Requirements

- **bash** 4.0+
- **yq** + **jq** - use the apt packages: `sudo apt update && sudo apt install -y yq jq`.
  The script also handles the snap/mikefarah `yq`,
  but apt is recommended (`snap install yq` emits YAML by default unless given `-o=json`).
- **wazuh-regex** + its shared libraries - installed by `./install-wazuh-regex.sh` in the next step.

## Installation

```bash
# 1. Install wazuh-regex + shared libraries (no root required)
./install-wazuh-regex.sh
#    optionally pin a specific wazuh-manager version:
WAZUH_MANAGER_VERSION=4.9.1-1 ./install-wazuh-regex.sh

# 2. (Optional) refresh the bundled policies from upstream Wazuh.
#    The repo already ships cis_ubuntu26-04.yml, cis_ubuntu24-04.yml and cis_ubuntu22-04.yml.
curl -sSfLo ./cis_ubuntu26-04.yml \
  https://raw.githubusercontent.com/wazuh/wazuh/refs/heads/main/ruleset/sca/ubuntu/cis_ubuntu26-04.yml
```

> `LD_LIBRARY_PATH` defaults to `./wazuh-lib`. If you keep a manual copy elsewhere, point the script at it with `-wl <PATH>`.

> **Exit code**: `0` = no compliance failures, `1` = at least one check failed, `2` = script/config error.
> A red CI run therefore means the policy found issues - not that the script crashed.

## Options

| Short  | Long                    | Description                                           |
| ------ | ----------------------- | ----------------------------------------------------- |
| `-h`   | `--help`                | Show help                                             |
| `-i`   | `--id <ID>`             | Run only the check with the given ID                  |
| `-f`   | `--file <FILE>`         | SCA YAML file (default `./cis_ubuntu24-04-v2024.yml`) |
| `-wr`  | `--wazuh-regex <PATH>`  | Path to wazuh-regex binary (default `./wazuh-regex`)  |
| `-wl`  | `--wazuh-libs <PATH>`   | wazuh lib directory (default `./wazuh-lib`)           |
| `-soc` | `--skip-os-check`       | Skip OS requirement validation                        |
| `-pdc` | `--print-detail-check`  | Print per-check result                                |
| `-pao` | `--print-actual-output` | Print actual command output (requires `-pdc`)         |
| `-psc` | `--print-section-count` | Print the rule count per CIS section                  |

## Supported Wazuh SCA Features

| Feature                                                                 | Status                                 |
| ----------------------------------------------------------------------- | -------------------------------------- |
| `c:` / `f:` / `d:` rule types (incl. nested `d:` → file → content)      | ✅                                     |
| `p:` process checks                                                     | ✅ (not exercised by bundled policies) |
| `r:` / `!r:` regex, `n:` / `!n:` numeric with `compare >= <= > < == !=` | ✅                                     |
| `not` negation, `&&` chains                                             | ✅                                     |
| `condition: all` / `any` / `one` / `none`                               | ✅                                     |
| `requirements` (OS validation)                                          | ✅                                     |
| `compliance` mapping; per-section reports (`-psc`) via CIS ref comments | ✅                                     |
| Variables `${var}`, Windows `registry:`                                 | ❌ Not implemented                     |

## SCA :: work in progress :: CIS files

Coverage is tracked against the [CIS Ubuntu 24.04 LTS benchmark](https://github.com/MVladislav/ansible-cis-ubuntu-2404). Per section, the format is `(total benchmark rules) (checks implemented in the policy) (-missing)`.

### CIS Ubuntu 24.04 (`cis_ubuntu24-04-v2024.yml`) - `95 pass / 148 fail / 42 N/A`

| Section | Total | Covered | Missing |
| :------ | ----: | ------: | ------: |
| 1       |    66 |      63 |      -3 |
| 2       |    43 |      42 |      -1 |
| 3       |    18 |      18 |       0 |
| 4       |    29 |      23 |      -6 |
| 5       |    71 |      68 |      -3 |
| 6       |    62 |      53 |      -9 |
| 7       |    23 |      18 |      -5 |

Results are measured on the author's host via `./sca.sh -soc -pdc -psc` (`-soc` skips OS-version validation);
your numbers will differ based on your configuration and hardening state.

## CI/CD

- **SCA workflow** (`.github/workflows/sca.yml`): on push/PR to `main` it installs wazuh-regex via `./install-wazuh-regex.sh`,
  then runs the script against each bundled policy through a `strategy.matrix` (`fail-fast: false`).
  Reports are uploaded as artifacts even on failure (`if: always()`).
- **Renovate** (`.github/renovate.json`): keeps GitHub Actions and pre-commit hooks up to date; grouped and auto-merged.
  Requires installing the Renovate GitHub App for the repository.

## Development

```bash
pre-commit install        # install hooks (codespell, yamllint, shellcheck, prettier, gitleaks, ...)
pre-commit run --all-files
shellcheck sca.sh         # lint the script
```

1. Fork and create a feature branch.
2. Make your changes.
3. Run pre-commit and `shellcheck`.
4. Open a pull request with the `pull_request_detailed.md` template.

## References

- [Wazuh SCA documentation](https://documentation.wazuh.com/current/user-manual/capabilities/sec-config-assessment/creating-custom-policies.html)
- [Wazuh Regex tool documentation](https://documentation.wazuh.com/current/reference/tools/wazuh-regex.html)
- [Wazuh SCA policy repository](https://github.com/wazuh/wazuh/tree/main/ruleset/sca)
- [CIS Benchmarks](https://www.cisecurity.org/cis-benchmarks/)
- [Ansible CIS Ubuntu 24.04](https://github.com/MVladislav/ansible-cis-ubuntu-2404)
- [Ansible CIS Ubuntu 22.04](https://github.com/MVladislav/ansible-cis-ubuntu-2204)
- Wazuh SCA Rulesets
  - [CIS Ubuntu 26.04](https://github.com/wazuh/wazuh/blob/main/ruleset/sca/ubuntu/cis_ubuntu26-04.yml)
  - [CIS Ubuntu 24.04](https://github.com/wazuh/wazuh/blob/main/ruleset/sca/ubuntu/cis_ubuntu24-04.yml)
- Wazuh Issues
  - [Create a test tool for SCA rules](https://github.com/wazuh/wazuh/issues/7623)
  - [Create SCA policy for Ubuntu 24.04 LTS](https://github.com/wazuh/wazuh/issues/23194)
- Other
  - <https://gist.github.com/MVladislav/b186d7dc6f151301cdd7b3943993d47c>

## License

MIT - see [LICENSE](LICENSE).
