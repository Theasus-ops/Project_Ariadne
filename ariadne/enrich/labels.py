"""Address attribution / labeling (Phase 4).

A LabelStore maps blockchain addresses to known entities: sanctioned wallets,
exchanges, mixers, ransomware or scam clusters. Labels are what turn a raw trace
("value reached a high-activity address") into intelligence ("value reached a
sanctioned mixer").
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from enum import Enum
from pathlib import Path
from typing import Iterable, Optional


class LabelCategory(str, Enum):
    SANCTIONED = "sanctioned"
    FROZEN = "frozen"      # frozen/blacklisted by a stablecoin issuer (Tether/Circle)
    RANSOMWARE = "ransomware"
    DARKNET = "darknet"
    SCAM = "scam"
    MIXER = "mixer"
    BRIDGE = "bridge"      # cross-chain bridge (chain-hop break-point)
    DEX = "dex"            # decentralized exchange / swap router (asset-swap break-point)
    GAMBLING = "gambling"
    ATM = "atm"            # crypto ATM / kiosk operator (physical cash-out point)
    EXCHANGE = "exchange"
    SERVICE = "service"
    OTHER = "other"


# Higher = more investigative interest. Used to rank findings and to break ties
# when one address carries more than one label.
CATEGORY_RISK: dict[LabelCategory, int] = {
    LabelCategory.SANCTIONED: 100,
    LabelCategory.FROZEN: 92,
    LabelCategory.RANSOMWARE: 90,
    LabelCategory.DARKNET: 85,
    LabelCategory.SCAM: 80,
    LabelCategory.MIXER: 70,
    LabelCategory.BRIDGE: 55,
    LabelCategory.ATM: 52,   # crypto-ATM cash-out is a FATF-flagged high-risk off-ramp
    LabelCategory.DEX: 45,
    LabelCategory.GAMBLING: 40,
    LabelCategory.EXCHANGE: 30,
    LabelCategory.SERVICE: 20,
    LabelCategory.OTHER: 10,
}

HIGH_RISK = {
    LabelCategory.SANCTIONED,
    LabelCategory.FROZEN,
    LabelCategory.RANSOMWARE,
    LabelCategory.DARKNET,
    LabelCategory.SCAM,
    LabelCategory.MIXER,
}


@dataclass(frozen=True)
class Label:
    address: str
    category: LabelCategory
    name: str
    source: str
    description: str = ""

    @property
    def risk(self) -> int:
        return CATEGORY_RISK.get(self.category, 0)


def norm_addr(address: str) -> str:
    """EVM (0x) addresses are case-insensitive; keep Bitcoin base58 as-is."""
    return address.lower() if address.startswith("0x") else address


def data_dir() -> Path:
    return Path(__file__).resolve().parent.parent / "data"


def default_labels_path() -> Path:
    return data_dir() / "labels.json"


def ofac_labels_path() -> Path:
    return data_dir() / "ofac_sanctioned.json"


def intel_labels_path() -> Path:
    return data_dir() / "intel_labels.json"


class LabelStore:
    def __init__(self) -> None:
        self._by_address: dict[str, Label] = {}

    def __len__(self) -> int:
        return len(self._by_address)

    def add(self, label: Label) -> None:
        key = norm_addr(label.address)
        existing = self._by_address.get(key)
        # keep the higher-risk label if an address appears more than once
        if existing is None or label.risk >= existing.risk:
            self._by_address[key] = label

    def extend(self, labels: Iterable[Label]) -> None:
        for lab in labels:
            self.add(lab)

    def get(self, address: str) -> Optional[Label]:
        return self._by_address.get(norm_addr(address))

    @classmethod
    def load(cls, *paths: Path) -> "LabelStore":
        store = cls()
        for p in paths:
            store.load_file(p)
        return store

    def load_file(self, path: Path) -> int:
        path = Path(path)
        if not path.exists():
            return 0
        payload = json.loads(path.read_text(encoding="utf-8"))
        count = 0
        for entry in payload.get("labels", []):
            try:
                category = LabelCategory(entry.get("category", "other"))
            except ValueError:
                category = LabelCategory.OTHER
            self.add(
                Label(
                    address=entry["address"],
                    category=category,
                    name=entry.get("name", ""),
                    source=entry.get("source", ""),
                    description=entry.get("description", ""),
                )
            )
            count += 1
        return count


def write_labels(labels: Iterable[Label], path: Path, note: str = "") -> int:
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    label_list = list(labels)
    payload = {
        "note": note,
        "labels": [
            {
                "address": lab.address,
                "category": lab.category.value,
                "name": lab.name,
                "source": lab.source,
                "description": lab.description,
            }
            for lab in label_list
        ],
    }
    path.write_text(json.dumps(payload, indent=2), encoding="utf-8")
    return len(label_list)
