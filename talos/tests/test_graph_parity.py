from __future__ import annotations

from talos.graph.discovery import build_tool_graph, graph_summary
from talos.harness.langchain_adapter import LangChainAdapter
from talos.harness.native_adapter import NativeAdapter


def test_graph_identical_across_adapters(native_server_url, langchain_server_url):
    native = NativeAdapter(native_server_url)
    native.connect()
    lc = LangChainAdapter(langchain_server_url)
    lc.connect()

    g_native = build_tool_graph(native.list_tools())
    g_lc = build_tool_graph(lc.list_tools())

    assert set(g_native.nodes) == set(g_lc.nodes)
    assert set(g_native.edges) == set(g_lc.edges)
    for n in g_native.nodes:
        assert dict(g_native.nodes[n]) == dict(g_lc.nodes[n])


def test_graph_classifies_known_tools_correctly(native_server_url):
    native = NativeAdapter(native_server_url)
    native.connect()
    g = build_tool_graph(native.list_tools())
    summary = graph_summary(g)

    assert summary["financial_tools"] == ["issue_refund"]
    assert summary["external_comm_tools"] == ["send_email"]
    assert set(summary["read_only_tools"]) == {"lookup_order", "search_kb"}
    assert set(summary["free_text_sources"]) == {"lookup_order", "search_kb"}
    # direct-injection surface reaches both side-effecting tools
    assert ("user_input", "issue_refund") in summary["direct_injection_edges"]
    assert ("user_input", "send_email") in summary["direct_injection_edges"]
