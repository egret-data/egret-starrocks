"""The verdict model of the probes: a check is only ENFORCED when its sight control succeeded.

A probe check is not a gate (checks.py is): on most of these paths neither image is patched, so a LEAK is
the measurement. What must fail the run is a check that cannot see (BLIND) or that broke (ERROR).
"""
import dataclasses
import enum
import sys
from collections.abc import Callable


class Verdict(enum.Enum):
    ENFORCED = "ENFORCED"
    LEAK = "LEAK"
    BLIND = "BLIND"
    NA = "N/A"
    SKIP = "SKIP"
    ERROR = "ERROR"


class Probe(enum.Enum):
    HIVE = "hive"
    JDBC = "jdbc"
    PAIMON = "paimon"
    STREAM_LOAD = "stream-load"
    ROUTINE_LOAD = "routine-load"
    IN_NAMESPACE = "in-namespace"


def skipped_probes(env_value: str) -> set[Probe]:
    """Parse PROBE_SKIP, a comma list of Probe names. An unknown name stops the run with exit 2."""
    names = [n.strip() for n in env_value.split(",") if n.strip()]
    known = {p.value: p for p in Probe}
    unknown = [n for n in names if n not in known]
    if unknown:
        print(f"PROBE_SKIP names unknown probes: {', '.join(unknown)} (known: {', '.join(known)})", file=sys.stderr)
        raise SystemExit(2)
    return {known[n] for n in names}


@dataclasses.dataclass
class ProbeCheck:
    id: str                                   # "C2-jdbc", "C14-paimon", ...
    probe: Probe
    name: str
    sight: Callable[[], bool]                 # True when the harness can see the leak content
    actual: Callable[[], object]
    leaked: Callable[[object], bool]          # True when `actual` carries what policies refuse
    na_reason: Callable[[], "str | None"] = lambda: None


# sqlpaths' DENIED codes (5203, 5204, 5210-5214): sqlpaths.run() turns them into the string "DENIED", the
# normal refusal result. Any other "ERROR ..." string it returns is a failed request, not a result.
DENIED_CODES = (5203, 5204, 5210, 5211, 5212, 5213, 5214)


def _is_request_failure(actual: object) -> bool:
    """sqlpaths helpers never raise: a failure comes back as "ERROR <errno or class>: <message>"."""
    if not isinstance(actual, str) or not actual.startswith("ERROR "):
        return False
    return not any(actual.startswith(f"ERROR {code}") for code in DENIED_CODES)


def _evaluate(c: ProbeCheck, skipped: set[Probe]) -> tuple[Verdict, object]:
    if c.probe in skipped:
        return Verdict.SKIP, f"PROBE_SKIP={c.probe.value}"
    try:
        reason = c.na_reason()
        if reason is not None:
            return Verdict.NA, reason
        if not c.sight():
            return Verdict.BLIND, "the sight control failed: a refusal here proves nothing"
        actual = c.actual()
        if _is_request_failure(actual):
            return Verdict.ERROR, actual
        return (Verdict.LEAK if c.leaked(actual) else Verdict.ENFORCED), actual
    except Exception as e:  # a broken check must report, not stop the run
        return Verdict.ERROR, f"{type(e).__name__}: {e}"


def run_checks(checks: list[ProbeCheck], skipped: set[Probe]) -> int:
    """Print one line per check and a summary; return 1 when a check is BLIND or ERROR, else 0."""
    counts = {v: 0 for v in Verdict}
    for c in checks:
        verdict, shown = _evaluate(c, skipped)
        counts[verdict] += 1
        text = str(shown)
        if len(text) >= 110:
            text = text[:107] + "..."
        print(f"{verdict.value}  [probe:{c.probe.value}]  {c.id} {c.name}  {text}")
    print("\n" + "  ".join(f"{v.value} {counts[v]}" for v in Verdict))
    return 1 if counts[Verdict.BLIND] or counts[Verdict.ERROR] else 0


def canary_hits(log: str, marker: str) -> list[str]:
    """The canary's logged `<path> <peer>` lines that contain `marker`."""
    try:
        with open(log) as f:
            return [line.rstrip("\n") for line in f if marker in line]
    except FileNotFoundError:
        return []
