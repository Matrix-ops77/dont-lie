"""Lightweight CRM lead pipeline."""
from .lead_pipe import (
    CRMPipeline,
    CRMPipelineError,
    Lead,
    STATUSES,
    load,
    persistence_path,
    save,
)

__all__ = [
    "CRMPipeline",
    "CRMPipelineError",
    "Lead",
    "STATUSES",
    "load",
    "persistence_path",
    "save",
]
