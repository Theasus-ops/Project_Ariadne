"""Import OFAC-sanctioned cryptocurrency addresses (Phase 4).

The US Treasury's OFAC SDN list includes "Digital Currency Address" identifiers
for sanctioned wallets. This module downloads the official SDN XML and extracts
those addresses as SANCTIONED labels -- the authoritative source for the single
highest-signal finding a money tracer can produce: dirty funds arriving at a
sanctioned wallet.
"""

from __future__ import annotations

import io
import xml.etree.ElementTree as ET

import requests

from .labels import Label, LabelCategory

OFAC_SDN_XML_URL = "https://www.treasury.gov/ofac/downloads/sdn.xml"


def _local(tag: str) -> str:
    """Strip the XML namespace from a tag name."""
    return tag.split("}")[-1]


def _child_text(elem, name: str) -> str:
    for child in elem:
        if _local(child.tag) == name and child.text:
            return child.text.strip()
    return ""


def _entry_name(entry) -> str:
    last = _child_text(entry, "lastName")
    first = _child_text(entry, "firstName")
    if first and last:
        return f"{first} {last}"
    return last or first or "OFAC SDN entity"


def parse_sdn(source) -> list[Label]:
    """Parse an OFAC SDN XML stream, returning SANCTIONED labels for crypto addresses."""
    labels: list[Label] = []
    for _event, elem in ET.iterparse(source, events=("end",)):
        if _local(elem.tag) != "sdnEntry":
            continue
        name = _entry_name(elem)
        for node in elem.iter():
            if _local(node.tag) != "id":
                continue
            id_type = _child_text(node, "idType")
            id_number = _child_text(node, "idNumber")
            if id_number and id_type.startswith("Digital Currency Address"):
                labels.append(
                    Label(
                        address=id_number,
                        category=LabelCategory.SANCTIONED,
                        name=name,
                        source="OFAC SDN",
                        description=id_type,
                    )
                )
        elem.clear()
    return labels


def import_ofac(url: str = OFAC_SDN_XML_URL, timeout: float = 120.0) -> list[Label]:
    resp = requests.get(url, timeout=timeout, headers={"User-Agent": "Ariadne/0.1"})
    resp.raise_for_status()
    return parse_sdn(io.BytesIO(resp.content))
