# Publishing TBHM 4.2.7

## Work from a dedicated publication checkout

Use `~/publish/TBHM` for publication. Keep operating scans in their existing tool
directory and retain assessment outputs and durable AI memory outside this
checkout. The publication helper updates documentation and ignore rules and
excludes identified engagement-derived diagnostic records. It preserves their
original bytes in a private backup outside the checkout, along with the original
versions of the generalized review summaries. Runtime source and the existing
project notice are preserved.

The distribution's installer verifies every manifest entry before creating a
virtual environment. Adding `.gitignore` or editing README changes the packaged
tree. The publication helper first checks the complete original inventory, then
updates the manifest for its exact documented edits. It refuses unexpected
files or changed runtime source instead of accepting a new arbitrary baseline.

Git ignore rules do not control `scripts/package_release.py` or replace a
secret review. Keep all private logs, state, backups and generated test output
outside the checkout. Do not run a manifest writer simply to hide an integrity
failure: investigate the changed or unexpected files first.

## Resolve the source license

Read `NOTICE.md`. The supplied notice records that the original project archive
had no project license and retained existing author rights. A public repository
and the bundled dependency licenses do not themselves grant a new license for
the original source. The copyright holder must select and grant the intended
license. The preparation kit includes a proposed MIT text outside the payload;
the helper does not install or claim approval of that proposal.

Preserve third-party notices. Review the sources of any separately added code,
templates and wordlists. After an authorized licensing edit, verify the exact
diff and regenerate the current manifest before the installation/clone checks.

## Check secrets before the first commit

Install Gitleaks from Kali's package repository if it is not already installed:

```sh
sudo apt install gitleaks
```

Run `audit_secrets.py` from the preparation kit, keeping the kit outside the
checkout. It uses Gitleaks `dir` mode for the full working tree, an explicit
configuration extending default rules, an empty ignore file, redacted output,
and positive/negative local controls. Reports are stored outside the checkout.
It does not contact credential providers or validate a credential by using it.

A possible-secret result needs review. A security framework contains detector
patterns and synthetic test credentials; verify each apparent match using its
file and line before allowing it. Do not blanket-exclude tests, source code or
provenance. A missing scanner, malformed report or failed control is not a pass.
If a real credential is found, remove it from the publication copy and revoke
or rotate it through the owning service. The publication helper must not be used
to overwrite such subsequent manual edits.

## Install and validate the publication copy

Choose an available Python 3.12 interpreter; a current Kali system Python may be
a different minor version. For this operator's environment:

```sh
cd "$HOME/publish/TBHM"
bash install.sh --offline --python "$HOME/tools/TBHM-4.2.7/.venv/bin/python"
.venv/bin/python -m pip check
./tbhm --version
.venv/bin/python scripts/validate_v4_release.py
.venv/bin/python scripts/run_tests.py --source . --workers 1 \
  --output "$HOME/tbhm-work/publication/full-regression-v427.json"
```

These commands validate installation and packaged regression groups. They do
not start a live target campaign, require an Ollama model, or certify external
browser/scanner behavior. Retain the actual result JSON and investigate failures.

## Review staging and a fresh local clone

Only stage after the licensing and secret-review steps are resolved:

```sh
cd "$HOME/publish/TBHM"
git config core.autocrlf false
git add --all
git diff --cached --check
git diff --cached --stat
git status --short
```

Compare the staged inventory with the release manifest; no manifest member
should be accidentally ignored. Keep `vendor/wheels`, `vendor/licenses`, the Go
source and the included executable when distributing this offline package.
Changes to executable bits or line endings also affect package verification.

Set the commit name/email you want to make public, using your GitHub noreply
address if desired. Create the initial local commit after reviewing its content:

```sh
git commit -m "Publish TBHM 4.2.7 source and operator documentation"
```

Before pushing, create a local clone and install there. This catches files that
were available on your machine but omitted from Git:

```sh
TBHM_CLONE_PARENT=$(mktemp -d "$HOME/tbhm-work/publication/clone-check.XXXXXXXX")
git clone --no-local "$HOME/publish/TBHM" "$TBHM_CLONE_PARENT/TBHM"
cd "$TBHM_CLONE_PARENT/TBHM"
bash install.sh --offline --python "$HOME/tools/TBHM-4.2.7/.venv/bin/python"
.venv/bin/python -m pip check
./tbhm --version
.venv/bin/python scripts/validate_v4_release.py
```

The preparation kit and publication state are outside the repository and must
not be copied into its source tree. A later code change warrants the tests
appropriate to that change; documentation-only changes need not repeat an
already passing full suite unless they affect packaging or leave a concern.

## Create the public GitHub repository

Authenticate on your own machine. Do not paste access tokens or a device login
code into a chat, issue or README:

```sh
gh auth login --hostname github.com --git-protocol https --web
gh auth setup-git
gh api user --jq .login
```

Once the intended account, license, secret review and clone checks are confirmed:

```sh
cd "$HOME/publish/TBHM"
gh repo create TBHM --public --source . --remote origin --push \
  --description "Evidence-oriented security assessment orchestration with optional local AI"
gh repo view --json nameWithOwner,url,visibility
```

If that repository name already exists, inspect it before choosing another name
or attaching a remote. Do not force-push or overwrite an existing project.
Enable repository security features appropriate to the project, keep the known
limitations visible, and use controlled examples rather than real customer
reports or credentials in screenshots and issues.

## Build a release archive

After the final source tree and current manifest are verified:

```sh
cd "$HOME/publish/TBHM"
.venv/bin/python scripts/package_release.py \
  --output "$HOME/tbhm-work/publication/TBHM-4.2.7-linux-x86_64.zip"
```

This command verifies the existing manifest. It does not silently accept source
drift. Publish a checksum alongside the exact archive when creating a release;
an archive checksum detects byte changes but is not an independent signature.

## References

- [GitHub: adding locally hosted code](https://docs.github.com/en/migrations/importing-source-code/using-the-command-line-to-import-source-code/adding-locally-hosted-code-to-github)
- [GitHub: licensing a repository](https://docs.github.com/en/repositories/managing-your-repositorys-settings-and-features/customizing-your-repository/licensing-a-repository)
- [Kali: Gitleaks package](https://www.kali.org/tools/gitleaks/)
- [Gitleaks commands and configuration](https://github.com/gitleaks/gitleaks)
- [GitHub CLI: authentication](https://cli.github.com/manual/gh_auth_login)
- [GitHub CLI: repository creation](https://cli.github.com/manual/gh_repo_create)
