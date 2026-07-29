"""Lightweight CRM lead pipeline."""
from .lead_pipe import (
    STATUSES,
    CRMPipeline,
    CRMPipelineError,
    Lead,
    load,
    persistence_path,
    save,
)

__all__ = [
    "STATUSES",
    "CRMPipeline",
    "CRMPipelineError",
    "Lead",
    "load",
    "persistence_path",
    "save",
]
