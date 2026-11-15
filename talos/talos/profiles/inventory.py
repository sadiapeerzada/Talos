"""Convert an already supplied tool inventory; never contact a target."""
from __future__ import annotations

from talos.harness.base import ToolSpec
from talos.profiles.models import MetadataEvidence, TargetProfile, ToolProfile


def profile_from_tools(
    tools: list[ToolSpec], *, target_id: str, domain: str, source_id: str, reference: str,
) -> TargetProfile:
    """ToolSpec descriptions do not establish effects, permissions or trust."""
    evidence = MetadataEvidence(evidence_id="inventory", source_id=source_id, reference=reference,
                                origin="target_declaration", detail="Supplied tool inventory; semantics unresolved.")
    records = []
    for tool in tools:
        names = [p.name for p in tool.parameters]
        if len(names) != len(set(names)):
            raise ValueError("duplicate inventory parameter name")
        records.append(ToolProfile(
            name=tool.name, description=tool.description, evidence_ids=("inventory",),
            input_schema={"type": "object", "properties": {
                p.name: {"type": p.type, "description": p.description} for p in tool.parameters
            }, "required": [p.name for p in tool.parameters if p.required]},
        ))
    return TargetProfile(target_id=target_id, domain=domain, evidence=(evidence,), tools=tuple(records))
