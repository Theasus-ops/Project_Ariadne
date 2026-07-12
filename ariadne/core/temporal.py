"""Temporal intelligence — behavioural fingerprinting from transaction timing.

*When* money moves is intelligence, not just decoration. The timestamps on a
wallet's transactions carry a behavioural signature that survives address rotation:

  * **Active-hours / timezone.** People (and the bots they run) are active in their
    waking hours and quiet during their local night. Binning transactions by
    hour-of-day and finding the quiet window recovers a likely UTC offset — and a
    coarse *region hint*. This is a standard attribution technique and it is
    offered as exactly what it is: a probabilistic lead, never proof.
  * **Velocity.** The typical interval between movements separates automated,
    high-frequency laundering from patient, manual operation.
  * **Burstiness.** Regular clockwork (low variance) vs. bursty spikes (high
    variance) distinguishes a service/bot from an opportunistic actor.
  * **Dormancy.** A long-dormant wallet suddenly moving is itself an alert.

Everything here is a pure function of a list of unix timestamps, so it is fully
deterministic and offline-testable; the provider-backed helpers just gather them.
"""

from __future__ import annotations

import math
import statistics
from dataclasses import dataclass, field

# Assumed local hour of peak on-chain activity (mid-afternoon). The inferred
# offset aligns an actor's busiest hour to this; it is a coarse, honest heuristic.
_CANONICAL_LOCAL_PEAK = 14.0


# Coarse offset -> region hint. Deliberately broad; this is a lead, not a locate.
_REGION_BANDS = {
    -8: "US Pacific", -7: "US Mountain", -6: "US Central / Central America",
    -5: "US Eastern / western South America", -4: "Atlantic / western South America",
    -3: "eastern South America (Brazil/Argentina)", 0: "UK / Portugal / West Africa",
    1: "Western/Central Europe / West Africa", 2: "Eastern Europe (incl. Greece) / South Africa",
    3: "Moscow / Middle East / East Africa", 4: "Gulf / Caucasus", 5: "Pakistan / West Asia",
    6: "Bangladesh / Central Asia", 7: "SE Asia (Thailand/Vietnam)",
    8: "China / Singapore / Philippines", 9: "Japan / Korea", 10: "eastern Australia",
}


@dataclass
class TemporalProfile:
    events: int = 0
    first_seen: int | None = None
    last_seen: int | None = None
    active_days: int = 0
    hour_histogram: list = field(default_factory=lambda: [0] * 24)
    peak_hours: list = field(default_factory=list)
    quiet_hours: list = field(default_factory=list)
    likely_utc_offset: int | None = None
    region_hint: str = ""
    median_interval_s: float | None = None
    burstiness: float | None = None
    dormant: bool = False
    longest_gap_s: int | None = None

    def as_dict(self) -> dict:
        return {
            "events": self.events,
            "first_seen": self.first_seen,
            "last_seen": self.last_seen,
            "active_days": self.active_days,
            "hour_histogram_utc": self.hour_histogram,
            "peak_hours_utc": self.peak_hours,
            "quiet_hours_utc": self.quiet_hours,
            "likely_utc_offset": self.likely_utc_offset,
            "region_hint": self.region_hint,
            "median_interval_seconds": self.median_interval_s,
            "burstiness": self.burstiness,
            "dormant": self.dormant,
            "longest_gap_seconds": self.longest_gap_s,
        }

    def summary(self) -> str:
        if self.events == 0:
            return "No timestamped activity to profile."
        parts = [f"{self.events} timestamped movement(s)"]
        if self.likely_utc_offset is not None:
            sign = "+" if self.likely_utc_offset >= 0 else ""
            parts.append(f"activity clusters around UTC{sign}{self.likely_utc_offset} ({self.region_hint})")
        if self.median_interval_s is not None:
            parts.append(f"typical gap between moves ~{_human(self.median_interval_s)}")
        if self.burstiness is not None:
            parts.append("bursty" if self.burstiness > 1.0 else "regular/clockwork")
        if self.dormant:
            parts.append("currently DORMANT")
        return "; ".join(parts) + "."


def _human(seconds: float) -> str:
    if seconds < 90:
        return f"{seconds:.0f}s"
    if seconds < 5400:
        return f"{seconds / 60:.0f}m"
    if seconds < 172800:
        return f"{seconds / 3600:.1f}h"
    return f"{seconds / 86400:.1f}d"


def infer_utc_offset(hour_histogram: list) -> int | None:
    """Estimate the operator's UTC offset from the hour-of-day activity histogram.

    Hours are angles on a 24-hour circle; the activity-weighted **circular mean**
    gives the actor's busiest UTC hour robustly even when activity is sparse (a
    plain quiet-window search degenerates when many hours are empty). We then align
    that busiest hour to a canonical local afternoon peak and solve for the offset.
    Folded into (-12, +12]. A coarse, probabilistic lead — never a locate.
    """
    total = sum(hour_histogram)
    if total == 0:
        return None
    x = sum(c * math.cos(2 * math.pi * h / 24) for h, c in enumerate(hour_histogram))
    y = sum(c * math.sin(2 * math.pi * h / 24) for h, c in enumerate(hour_histogram))
    if abs(x) < 1e-9 and abs(y) < 1e-9:
        return None  # activity uniform around the clock — no signal
    mean_hour = (math.degrees(math.atan2(y, x)) / 15.0) % 24  # 360/24 = 15 deg per hour
    offset = round(_CANONICAL_LOCAL_PEAK - mean_hour)
    return ((offset + 12) % 24) - 12


def region_hint(offset: int | None) -> str:
    if offset is None:
        return ""
    return _REGION_BANDS.get(offset, f"UTC{'+' if offset >= 0 else ''}{offset} band")


def analyze(timestamps: list[int], dormant_days: int = 90, now: int | None = None) -> TemporalProfile:
    ts = sorted(t for t in timestamps if t)
    profile = TemporalProfile(events=len(ts))
    if not ts:
        return profile

    profile.first_seen = ts[0]
    profile.last_seen = ts[-1]
    profile.active_days = max(1, (ts[-1] - ts[0]) // 86400)

    hist = [0] * 24
    for t in ts:
        hist[int((t // 3600) % 24)] = hist[int((t // 3600) % 24)] + 1
    profile.hour_histogram = hist
    peak = max(hist)
    profile.peak_hours = [h for h, c in enumerate(hist) if c == peak and peak > 0]
    profile.quiet_hours = [h for h, c in enumerate(hist) if c == 0]
    profile.likely_utc_offset = infer_utc_offset(hist)
    profile.region_hint = region_hint(profile.likely_utc_offset)

    if len(ts) >= 2:
        intervals = [b - a for a, b in zip(ts, ts[1:], strict=False)]
        profile.median_interval_s = float(statistics.median(intervals))
        profile.longest_gap_s = max(intervals)
        mean = statistics.mean(intervals)
        if mean > 0 and len(intervals) >= 2:
            profile.burstiness = statistics.pstdev(intervals) / mean

    reference = now if now is not None else ts[-1]
    profile.dormant = (reference - ts[-1]) > dormant_days * 86400 if now is not None else False
    return profile


def from_trace(result) -> TemporalProfile:
    """Profile the timing of the traced money flow itself (edge timestamps)."""
    times = [e.first_time for e in result.edges.values() if e.first_time is not None]
    return analyze(times)


def profile_address(provider, address: str, max_txs: int = 200) -> TemporalProfile:
    """Fetch an address's transactions and profile their timing."""
    try:
        txs = provider.get_transactions(provider.normalize(address), max_txs)
    except Exception:
        return TemporalProfile()
    return analyze([t.block_time for t in txs if t.block_time])
