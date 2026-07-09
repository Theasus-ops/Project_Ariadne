"""Provider interface. Each supported chain implements this."""

from __future__ import annotations

from abc import ABC, abstractmethod

from ..models import BTC, Asset, Transaction


class Provider(ABC):
    name: str = "base"
    asset_info: Asset = BTC

    @staticmethod
    def normalize(address: str) -> str:
        """Canonicalize an address. EVM (0x) addresses are case-insensitive hex;
        Bitcoin base58 is case-sensitive, so it is left untouched."""
        return address.lower() if address.startswith("0x") else address

    @abstractmethod
    def address_tx_count(self, address: str) -> int:
        """Total confirmed tx count for an address.

        Used to detect high-activity service addresses (exchanges, mixers)
        without having to download their entire history.
        """

    def address_received(self, address: str) -> int | None:
        """All-time value received by an address, in the smallest unit.

        Used as the taint haircut denominator. Return None if the chain has no
        cheap way to obtain it (the taint engine then falls back to traced flow).
        """
        return None

    def latest_block_height(self) -> int:
        raise NotImplementedError(f"{self.name} does not support live monitoring yet")

    def get_block_transactions(self, height: int, max_txs: int = 25) -> list[Transaction]:
        raise NotImplementedError(f"{self.name} does not support live monitoring yet")

    def get_mempool_transactions(self, max_txs: int = 10) -> list[Transaction]:
        raise NotImplementedError(f"{self.name} does not support mempool monitoring yet")

    @abstractmethod
    def get_transactions(self, address: str, max_txs: int) -> list[Transaction]:
        """Return up to ``max_txs`` normalized transactions for the address, newest first."""
