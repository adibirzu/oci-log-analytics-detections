"""Thin OCI Functions entrypoint for the canonical exporter package."""

from scripts.splunk_evidence_exporter.handler import handler


__all__ = ["handler"]
