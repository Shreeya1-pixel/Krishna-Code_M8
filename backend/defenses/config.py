"""Defense configuration — toggleable per-control."""
from __future__ import annotations
import os
from dataclasses import dataclass

@dataclass
class DefenseConfig:
    enabled: bool = True
    classifier: bool = True
    policy_broker: bool = True
    output_guard: bool = True

    def to_dict(self):
        return {
            "enabled": self.enabled,
            "classifier": self.classifier,
            "policy_broker": self.policy_broker,
            "output_guard": self.output_guard,
        }

    @classmethod
    def from_dict(cls, d: dict) -> "DefenseConfig":
        return cls(
            enabled=d.get("enabled", True),
            classifier=d.get("classifier", True),
            policy_broker=d.get("policy_broker", True),
            output_guard=d.get("output_guard", True),
        )

    @classmethod
    def vulnerable() -> "DefenseConfig":
        return DefenseConfig(enabled=False, classifier=False, policy_broker=False, output_guard=False)

    @classmethod
    def defended() -> "DefenseConfig":
        return DefenseConfig(enabled=True, classifier=True, policy_broker=True, output_guard=True)


_config = DefenseConfig()


def get_defense_config() -> DefenseConfig:
    return _config


def set_defense_config(cfg: DefenseConfig):
    global _config
    _config = cfg
