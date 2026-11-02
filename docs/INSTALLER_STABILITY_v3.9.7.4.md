# TBHM v3.9.7.4 Installer Stability

v3.9.7.4 preserves the v3.9.7.3 installer-isolation model and extends the
firmware dependency plan without installing high-risk research frameworks into
TBHM's shared Python environment.

## Preserved installer controls

- exact package checks and apt preflight;
- bounded retries for transient apt failures;
- user-owned npm prefix;
- isolated Python environments for optional applications;
- compatibility checks before pip installation;
- locked or validated recipes where required;
- explicit unavailable/incompatible/skipped states instead of false success;
- plan-only legacy cleanup by default;
- no unrestricted shell execution in installer helpers.

## Firmware additions

The installer can prepare common static firmware dependencies, including
archive/decompression tools, `binwalk`, SquashFS utilities, QEMU user-mode
helpers where the distribution provides them, and `unblob` through a package or
isolated environment when available.

EMBA, RouterSploit, FirmAE, FIRMADYNE and similar research platforms remain
operator-managed because their installation models and host requirements vary.
TBHM detects or imports them rather than silently cloning and executing them.

## Validation

`bash -n` passed for the release scripts, and all v3.9.7.3 installer regression
tests plus the v3.9.7.4 reverse tests passed.
