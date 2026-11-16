"""Shared config accessor.

Tolerates a Config implementation that has no `attack` section, so the module
works whether or not config.yaml has been updated yet.
"""
from __future__ import annotations


def attack_cfg(cfg) -> dict:
    return getattr(cfg, "attack", None) or {}