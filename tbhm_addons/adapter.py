"""
tbhm_addons.adapter
==================

Integration shim so the three modules drop into TBHM v2.24 no matter what
execution model the orchestrator uses. Every phase is exposed as BOTH:

  * a plain function  ->  run_phase(phase_id, config) -> dict
  * a class instance  ->  Phase(...).run() -> dict

so whether v2.24 calls functions, instantiates classes, or shells out, there
is a matching entrypoint. Each phase auto-wires the RedTeamLogger so logging,
exception capture, and reproducibility happen without the orchestrator knowing
anything about logging_core.

Register into TBHM by importing ADDON_PHASES and merging it into whatever
registry the tool keeps (dict of phase_id -> callable). If you don't know the
registry shape, call `describe()` to print the phase IDs and hand them to the
orchestrator manually.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Callable, Optional

from .logging_core import RedTeamLogger, RunContext
from .mod_sqli import SqliModule
from .mod_net_ad import NetAdModule
from .mod_service_primitive import ServicePrimitiveModule


def _make_logger(config: dict[str, Any]) -> RedTeamLogger:
    ctx = RunContext(
        engagement=config.get("engagement", "UNSPECIFIED"),
        target=config.get("target", ""),
        pivot_host=config.get("pivot_host", ""),
        session_handle=config.get("session_handle", ""),
        roe_ref=config.get("roe_ref", ""),
    )
    run_root = config.get("run_root", "./tbhm_run")
    return RedTeamLogger(run_root, ctx=ctx,
                         capture_background=config.get("capture_bg", True))


# -- phase functions --------------------------------------------------------
def phase_sqli(config: dict[str, Any],
               logger: Optional[RedTeamLogger] = None) -> dict[str, Any]:
    log = logger or _make_logger(config)
    silent = config.get("silent", False)
    with log.phase(config.get("phase_id", "ADD-SQLI"),
                   "SQL injection detection", silent=silent) as ph:
        mod = SqliModule(
            delay_between_requests=config.get("req_delay", 1.0),
            time_delay_s=config.get("time_delay_s", 5),
            verify_tls=config.get("verify_tls", False),
        )
        result = mod.run(config["target"], phase=ph,
                         run_sqlmap_on_hit=config.get("sqlmap_fallback", False))
    return result.to_dict()


def phase_net_ad(config: dict[str, Any],
                 logger: Optional[RedTeamLogger] = None) -> dict[str, Any]:
    log = logger or _make_logger(config)
    silent = config.get("silent", False)
    with log.phase(config.get("phase_id", "ADD-NETAD"),
                   "network + AD read-only review", silent=silent) as ph:
        mod = NetAdModule(nmap_timing=config.get("nmap_timing", "-T3"))
        if config.get("cidr"):
            mod.discover_hosts(config["cidr"], phase=ph)
        if config.get("fingerprint_target"):
            mod.fingerprint(config["fingerprint_target"], phase=ph)
        if config.get("dc_ip") and config.get("base_dn"):
            result = mod.review_ad(
                config["dc_ip"], config["base_dn"],
                config["bind_user"], config["bind_password"],
                phase=ph, use_ssl=config.get("ldaps", False))
        else:
            from .mod_net_ad import NetAdResult
            result = NetAdResult()
            result.errors.append("no dc_ip/base_dn supplied; ran network only")
    return result.to_dict()


def phase_service_primitive(config: dict[str, Any],
                            logger: Optional[RedTeamLogger] = None
                            ) -> dict[str, Any]:
    log = logger or _make_logger(config)
    silent = config.get("silent", False)
    with log.phase(config.get("phase_id", "ADD-SVCPRIM"),
                   "service execution-primitive detection", silent=silent) as ph:
        mod = ServicePrimitiveModule(
            prove_writable=config.get("prove_writable", False))
        result = mod.check_host(phase=ph)
    return result.to_dict()


# -- class wrappers (for orchestrators that expect .run()) ------------------
@dataclass
class _PhaseClass:
    fn: Callable[..., dict[str, Any]]
    config: dict[str, Any]
    def run(self) -> dict[str, Any]:
        return self.fn(self.config)


def make_phase_class(phase_id: str):
    fn = ADDON_PHASES[phase_id]
    def factory(config: dict[str, Any]) -> _PhaseClass:
        return _PhaseClass(fn=fn, config=config)
    return factory


# -- registry ---------------------------------------------------------------
ADDON_PHASES: dict[str, Callable[..., dict[str, Any]]] = {
    "ADD-SQLI": phase_sqli,
    "ADD-NETAD": phase_net_ad,
    "ADD-SVCPRIM": phase_service_primitive,
}

# map new phases onto the playbook branch IDs they extend, so coverage
# tracking in the master checklist stays consistent
BRANCH_MAP = {
    "ADD-SQLI":   ["BR09", "BR10", "IMP-03"],   # web/API + injection cards
    "ADD-NETAD":  ["BR06", "IMP-07", "FR-022"], # AD/identity
    "ADD-SVCPRIM":["BR07", "BR08", "IMP-07-049"],# endpoint/server hardening
}


def describe() -> str:
    lines = ["TBHM v2.24 add-on phases:"]
    for pid, fn in ADDON_PHASES.items():
        lines.append(f"  {pid:<12} -> {fn.__name__}  "
                     f"(extends {', '.join(BRANCH_MAP.get(pid, []))})")
    return "\n".join(lines)


def run_phase(phase_id: str, config: dict[str, Any]) -> dict[str, Any]:
    """Single generic entrypoint an orchestrator can call for any add-on."""
    if phase_id not in ADDON_PHASES:
        raise KeyError(f"unknown add-on phase: {phase_id}")
    return ADDON_PHASES[phase_id](config)


if __name__ == "__main__":
    print(describe())
