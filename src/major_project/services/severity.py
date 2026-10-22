"""Configurable, rule-based alert severity.

These labels help prioritise review. They are not calibrated probabilities and not a measure of
real-world risk.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Literal

SeverityLevel = Literal["informational", "medium", "high"]
ALERT_SEVERITIES: tuple[SeverityLevel, ...] = ("medium", "high")


@dataclass(frozen=True)
class SeverityPolicy:
    attack_threshold: float
    high_min_probability: float

    def __post_init__(self) -> None:
        if not 0 <= self.attack_threshold <= self.high_min_probability <= 1:
            raise ValueError("require 0 <= attack_threshold <= high_min_probability <= 1")

    def classify(self, is_attack: bool, attack_probability: float) -> SeverityLevel:
        if not is_attack:
            return "informational"
        return "high" if attack_probability >= self.high_min_probability else "medium"

    def describe(self) -> dict[str, str]:
        return {
            "informational": f"Predicted Benign (P(attack) < {self.attack_threshold:g}). No alert.",
            "medium": (
                f"Predicted Attack with {self.attack_threshold:g} <= P(attack) < "
                f"{self.high_min_probability:g}. Alert raised."
            ),
            "high": (
                f"Predicted Attack with P(attack) >= {self.high_min_probability:g}. Alert raised."
            ),
            "note": "Rule-based triage labels on an uncalibrated model score; not verified risk.",
        }
