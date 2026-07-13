"""Crypto-ATM (BATM) geolocation intelligence.

Crypto ATMs are a FATF-flagged high-risk off-ramp: cash out, weak KYC, physical
location. When a trace's cash-out is a crypto-ATM operator, an investigator wants
the *place* — a kiosk has CCTV, a landlord, and an operator who logs every session.

Ariadne builds a registry of physical crypto ATMs from **OpenStreetMap** via the
public, keyless Overpass API (operator, name, latitude/longitude, address). It is a
real, worldwide dataset that refreshes on demand (`ariadne atm-sync`).

What it can and cannot do — stated plainly, because overclaiming a location is a
serious failure:

  * On-chain data attributes a cash-out to an **operator** (via a labelled ATM
    address), not to one specific machine. Ariadne therefore surfaces that
    operator's physical kiosks as **candidate locations**; the exact machine, plus
    the customer's identity and session video, comes from the operator's records
    under lawful process. When an operator runs a single kiosk, the candidate *is*
    the location.
  * As a standalone OSINT tool it answers "which crypto ATMs are near this place?"
    — e.g. every machine within N km of a victim or a suspect's known address.
"""

from __future__ import annotations

import math
import sqlite3
import time
from pathlib import Path

import requests

# Public Overpass mirrors (keyless). Tried in order for resilience.
_OVERPASS_ENDPOINTS = [
    "https://overpass-api.de/api/interpreter",
    "https://overpass.kumi.systems/api/interpreter",
    "https://maps.mail.ru/osm/tools/overpass/api/interpreter",
]

# Nodes that represent a crypto ATM / kiosk in OSM tagging practice.
_OVERPASS_QUERY = """
[out:json][timeout:{timeout}];
(
  node["amenity"="atm"]["currency:XBT"="yes"]{bbox};
  node["amenity"="atm"]["currency:cryptocurrencies"="yes"]{bbox};
  node["amenity"="vending_machine"]["currency:XBT"="yes"]{bbox};
  node["amenity"="bureau_de_change"]["currency:XBT"="yes"]{bbox};
  node["payment:bitcoin"="yes"]["amenity"="atm"]{bbox};
  node["payment:cryptocurrencies"="yes"]["amenity"="atm"]{bbox};
);
out center tags;
"""


def haversine_km(lat1: float, lon1: float, lat2: float, lon2: float) -> float:
    r = 6371.0
    p1, p2 = math.radians(lat1), math.radians(lat2)
    dphi = math.radians(lat2 - lat1)
    dlmb = math.radians(lon2 - lon1)
    a = math.sin(dphi / 2) ** 2 + math.cos(p1) * math.cos(p2) * math.sin(dlmb / 2) ** 2
    return 2 * r * math.asin(math.sqrt(a))


class ATMRegistry:
    def __init__(self, path: str | Path = "knowledge/atm_registry.sqlite") -> None:
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._conn = sqlite3.connect(str(self.path))
        self._conn.row_factory = sqlite3.Row
        self._conn.executescript(
            """
            CREATE TABLE IF NOT EXISTS atms (
                osm_id TEXT PRIMARY KEY,
                operator TEXT, name TEXT,
                lat REAL, lon REAL,
                country TEXT, city TEXT, street TEXT,
                source TEXT, updated_at INTEGER
            );
            CREATE INDEX IF NOT EXISTS ix_atm_op ON atms(operator);
            CREATE INDEX IF NOT EXISTS ix_atm_country ON atms(country);
            """
        )
        self._conn.commit()

    # ---- ingestion ----
    @staticmethod
    def _fetch_overpass(bbox: tuple | None, timeout: int) -> list[dict]:
        bbox_clause = ""
        if bbox:
            s, w, n, e = bbox
            bbox_clause = f"({s},{w},{n},{e})"
        query = _OVERPASS_QUERY.format(timeout=timeout, bbox=bbox_clause)
        last_exc: Exception | None = None
        for endpoint in _OVERPASS_ENDPOINTS:
            try:
                resp = requests.post(
                    endpoint, data={"data": query}, timeout=timeout + 30,
                    headers={"User-Agent": "Ariadne/0.3 (crypto-atm-intel)"},
                )
                resp.raise_for_status()
                return resp.json().get("elements", [])
            except Exception as exc:  # try the next mirror
                last_exc = exc
                continue
        raise RuntimeError(f"All Overpass endpoints failed: {last_exc}")

    def sync_from_osm(self, bbox: tuple | None = None, timeout: int = 180) -> int:
        """Fetch crypto ATMs from OSM and upsert them. Returns the count stored.

        ``bbox`` = (south, west, north, east) to limit the region; None = worldwide.
        """
        elements = self._fetch_overpass(bbox, timeout)
        now = int(time.time())
        count = 0
        for el in elements:
            tags = el.get("tags", {})
            lat = el.get("lat") or (el.get("center") or {}).get("lat")
            lon = el.get("lon") or (el.get("center") or {}).get("lon")
            if lat is None or lon is None:
                continue
            operator = (tags.get("operator") or tags.get("brand") or tags.get("network")
                        or tags.get("name") or "unknown operator").strip()
            self._conn.execute(
                "INSERT INTO atms (osm_id, operator, name, lat, lon, country, city, street, source, updated_at) "
                "VALUES (?,?,?,?,?,?,?,?,?,?) ON CONFLICT(osm_id) DO UPDATE SET "
                "operator=excluded.operator, name=excluded.name, lat=excluded.lat, lon=excluded.lon, "
                "country=excluded.country, city=excluded.city, street=excluded.street, updated_at=excluded.updated_at",
                (
                    f"{el.get('type', 'node')}/{el.get('id')}", operator,
                    (tags.get("name") or "").strip(), float(lat), float(lon),
                    tags.get("addr:country") or "", tags.get("addr:city") or "",
                    " ".join(x for x in (tags.get("addr:street"), tags.get("addr:housenumber")) if x),
                    "OpenStreetMap", now,
                ),
            )
            count += 1
        self._conn.commit()
        return count

    def add(self, osm_id: str, operator: str, lat: float, lon: float,
            name: str = "", country: str = "", city: str = "", street: str = "") -> None:
        """Insert/replace a single machine (used by tests and manual curation)."""
        self._conn.execute(
            "INSERT OR REPLACE INTO atms (osm_id, operator, name, lat, lon, country, city, street, source, updated_at) "
            "VALUES (?,?,?,?,?,?,?,?,?,?)",
            (osm_id, operator, name, float(lat), float(lon), country, city, street, "manual", int(time.time())),
        )
        self._conn.commit()

    # ---- queries ----
    @staticmethod
    def _row(r: sqlite3.Row) -> dict:
        return {
            "osm_id": r["osm_id"], "operator": r["operator"], "name": r["name"],
            "lat": r["lat"], "lon": r["lon"], "country": r["country"],
            "city": r["city"], "street": r["street"],
            "osm_url": f"https://www.openstreetmap.org/{r['osm_id']}",
        }

    def near(self, lat: float, lon: float, radius_km: float = 5.0, limit: int = 25) -> list[dict]:
        # Cheap bounding-box prefilter, then exact haversine.
        dlat = radius_km / 111.0
        dlon = radius_km / (111.0 * max(0.1, math.cos(math.radians(lat))))
        rows = self._conn.execute(
            "SELECT * FROM atms WHERE lat BETWEEN ? AND ? AND lon BETWEEN ? AND ?",
            (lat - dlat, lat + dlat, lon - dlon, lon + dlon),
        ).fetchall()
        out = []
        for r in rows:
            d = haversine_km(lat, lon, r["lat"], r["lon"])
            if d <= radius_km:
                entry = self._row(r)
                entry["distance_km"] = round(d, 3)
                out.append(entry)
        out.sort(key=lambda x: x["distance_km"])
        return out[:limit]

    def by_operator(self, operator: str, limit: int = 100) -> list[dict]:
        rows = self._conn.execute(
            "SELECT * FROM atms WHERE lower(operator) LIKE ? ORDER BY country, city LIMIT ?",
            (f"%{operator.lower()}%", limit),
        ).fetchall()
        return [self._row(r) for r in rows]

    def operators(self, limit: int = 50) -> list[dict]:
        rows = self._conn.execute(
            "SELECT operator, COUNT(*) n FROM atms GROUP BY operator ORDER BY n DESC LIMIT ?",
            (limit,),
        ).fetchall()
        return [{"operator": r["operator"], "machines": r["n"]} for r in rows]

    def stats(self) -> dict:
        c = self._conn
        return {
            "machines": c.execute("SELECT COUNT(*) FROM atms").fetchone()[0],
            "operators": c.execute("SELECT COUNT(DISTINCT operator) FROM atms").fetchone()[0],
            "countries": c.execute("SELECT COUNT(DISTINCT country) FROM atms WHERE country != ''").fetchone()[0],
        }

    def close(self) -> None:
        self._conn.close()


def atm_intel_for_report(report: dict, registry: ATMRegistry) -> list[dict]:
    """For each crypto-ATM operator reached by the trace, list candidate kiosks."""
    intel: list[dict] = []
    seen: set[str] = set()
    for node in report.get("nodes", []):
        if node.get("category") != "atm":
            continue
        operator = (node.get("label") or "").strip()
        if not operator or operator.lower() in seen:
            continue
        seen.add(operator.lower())
        machines = registry.by_operator(operator, limit=50) if operator else []
        intel.append({
            "address": node.get("address"),
            "operator": operator,
            "machine_count": len(machines),
            "candidate_locations": machines[:25],
            "note": (
                "On-chain data attributes this cash-out to the operator, not one machine. "
                "The exact kiosk, the customer's identity, and session video come from the "
                "operator's records under lawful process."
            ),
        })
    return intel
