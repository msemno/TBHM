"""TBHM v2.24 add-on package: logging subsystem + three drop-in modules."""
from .logging_core import RedTeamLogger, RunContext, PhaseLogger
from .mod_sqli import SqliModule, SqliResult, SqliFinding
from .mod_net_ad import NetAdModule, NetAdResult, AdObservation
from .mod_service_primitive import (ServicePrimitiveModule, ServiceResult,
                                    ServiceFinding)
from .adapter import (ADDON_PHASES, BRANCH_MAP, run_phase, describe,
                      make_phase_class, phase_sqli, phase_net_ad,
                      phase_service_primitive)

__version__ = "3.0.0-integrated"
__all__ = [
    "RedTeamLogger", "RunContext", "PhaseLogger",
    "SqliModule", "SqliResult", "SqliFinding",
    "NetAdModule", "NetAdResult", "AdObservation",
    "ServicePrimitiveModule", "ServiceResult", "ServiceFinding",
    "ADDON_PHASES", "BRANCH_MAP", "run_phase", "describe",
    "make_phase_class", "phase_sqli", "phase_net_ad",
    "phase_service_primitive",
]
