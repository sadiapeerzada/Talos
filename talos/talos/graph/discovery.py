"""
Tool-graph discovery: turn a flat `list_tools()` result into a networkx
DiGraph that captures which tools have side effects, what permission level
that implies, and which tools could feed attacker-influenced data into
which other tools.

This is deliberately black-box: it only looks at what `TargetAgent.list_tools()`
returns (name, description, parameters). It never needs the target's source
code, which is what lets it work identically against either adapter.
"""

from __future__ import annotations

import networkx as nx

from talos.graph.classify import (
    classify_permission_level,
    classify_side_effect,
    has_free_text_sink,
    is_free_text_source,
)
from talos.harness.base import ToolSpec

USER_INPUT_NODE = "user_input"


def build_tool_graph(tools: list[ToolSpec]) -> nx.DiGraph:
    g = nx.DiGraph()
    g.add_node(USER_INPUT_NODE, kind="input_surface")

    info = {}
    for t in tools:
        se = classify_side_effect(t)
        perm = classify_permission_level(se)
        source = is_free_text_source(t)
        sink = has_free_text_sink(t)
        info[t.name] = {"side_effect": se, "permission": perm, "source": source, "sink": sink}
        g.add_node(
            t.name,
            kind="tool",
            side_effect=se.value,
            permission=perm.value,
            is_free_text_source=source,
            has_free_text_sink=sink,
            description=t.description,
        )

    # Direct-injection surface: user input reaches every side-effecting tool.
    for t in tools:
        if info[t.name]["side_effect"].value != "read_only":
            g.add_edge(USER_INPUT_NODE, t.name, kind="direct_injection_surface")

    # Indirect-injection surface: any free-text-returning tool feeding into
    # any side-effecting tool.
    for src in tools:
        if not info[src.name]["source"]:
            continue
        for dst in tools:
            if dst.name == src.name:
                continue
            if info[dst.name]["side_effect"].value != "read_only":
                g.add_edge(src.name, dst.name, kind="possible_injection_path")

    return g


def graph_summary(g: nx.DiGraph) -> dict:
    tool_nodes = [n for n, d in g.nodes(data=True) if d.get("kind") == "tool"]
    return {
        "tool_count": len(tool_nodes),
        "financial_tools": [n for n in tool_nodes if g.nodes[n]["side_effect"] == "financial"],
        "external_comm_tools": [n for n in tool_nodes if g.nodes[n]["side_effect"] == "external_comm"],
        "read_only_tools": [n for n in tool_nodes if g.nodes[n]["side_effect"] == "read_only"],
        "free_text_sources": [n for n in tool_nodes if g.nodes[n]["is_free_text_source"]],
        "direct_injection_edges": [(u, v) for u, v, d in g.edges(data=True) if d["kind"] == "direct_injection_surface"],
        "indirect_injection_edges": [(u, v) for u, v, d in g.edges(data=True) if d["kind"] == "possible_injection_path"],
    }
