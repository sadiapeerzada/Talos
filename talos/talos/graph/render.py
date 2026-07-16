"""Renders a tool graph (from graph/discovery.py) as Mermaid flowchart
source, suitable for embedding directly in a Markdown report."""

from __future__ import annotations

import networkx as nx

from talos.graph.discovery import USER_INPUT_NODE

_EMOJI = {"financial": "\U0001F4B0", "external_comm": "\U0001F4E7", "read_only": "\U0001F50D"}


def to_mermaid(g: nx.DiGraph) -> str:
    lines = ["graph LR"]

    for node, data in g.nodes(data=True):
        if node == USER_INPUT_NODE:
            lines.append(f'    {node}(["fa:fa-user user input"])')
            continue
        emoji = _EMOJI.get(data.get("side_effect"), "")
        perm = data.get("permission", "?")
        tag = " (free-text source)" if data.get("is_free_text_source") else ""
        lines.append(f'    {node}["{emoji} {node}<br/>{perm} priv{tag}"]')

    direct = [(u, v) for u, v, d in g.edges(data=True) if d.get("kind") == "direct_injection_surface"]
    indirect = [(u, v) for u, v, d in g.edges(data=True) if d.get("kind") == "possible_injection_path"]

    for u, v in direct:
        lines.append(f"    {u} --> {v}")
    for u, v in indirect:
        lines.append(f"    {u} -.->|possible injection path| {v}")

    return "\n".join(lines)
