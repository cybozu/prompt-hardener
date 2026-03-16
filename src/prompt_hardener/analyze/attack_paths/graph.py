"""Build a coarse attack graph from a normalized spec."""

from prompt_hardener.analyze.attack_paths.models import AttackGraph


def build_attack_graph(surface):
    # type: (NormalizedSpec) -> AttackGraph
    graph = AttackGraph()

    llm_id = graph.add_node("control", "llm")
    system_prompt_id = graph.add_node("asset", "system_prompt")
    response_channel_id = graph.add_node("asset", "response_channel")
    graph.add_edge(system_prompt_id, llm_id, "can_influence")
    graph.add_edge(llm_id, system_prompt_id, "can_read")
    graph.add_edge(llm_id, response_channel_id, "can_write")

    if surface.has_user_message_entrypoint:
        user_id = graph.add_node("entrypoint", "user_message")
        graph.add_edge(user_id, llm_id, "can_influence")

    if any(ds.is_untrusted for ds in surface.data_sources):
        retrieved_id = graph.add_node("entrypoint", "retrieved_content")
        graph.add_edge(retrieved_id, llm_id, "can_influence")

    if surface.tools:
        tool_result_id = graph.add_node("entrypoint", "tool_result")
        graph.add_edge(tool_result_id, llm_id, "can_influence")

    if any(server.is_untrusted for server in surface.mcp_servers):
        mcp_id = graph.add_node("entrypoint", "mcp_response")
        graph.add_edge(mcp_id, llm_id, "can_influence")

    if surface.has_persistent_memory:
        memory_id = graph.add_node("entrypoint", "persistent_memory")
        memory_store_id = graph.add_node("asset", "memory_store")
        graph.add_edge(memory_id, llm_id, "can_influence")
        graph.add_edge(llm_id, memory_store_id, "can_persist_to")

    if surface.scope == "multi_tenant":
        graph.add_node("asset", "cross_tenant_data")

    for tool in surface.tools:
        tool_id = graph.add_node("capability", tool.name, source_kind="tool")
        graph.add_edge(llm_id, tool_id, "can_trigger")
        if tool.can_modify_state:
            backend_state_id = graph.add_node("asset", "backend_state")
            graph.add_edge(tool_id, backend_state_id, "can_write")
        if tool.can_egress:
            external_id = graph.add_node("asset", "external_channel")
            graph.add_edge(tool_id, external_id, "can_send_to")
        if tool.can_persist_state or surface.has_persistent_memory:
            memory_store_id = graph.add_node("asset", "memory_store")
            graph.add_edge(tool_id, memory_store_id, "can_persist_to")
        if surface.scope == "multi_tenant":
            cross_tenant_id = graph.add_node("asset", "cross_tenant_data")
            graph.add_edge(tool_id, cross_tenant_id, "can_read")
            graph.add_edge(tool_id, cross_tenant_id, "can_write")

    for data_source in surface.data_sources:
        ds_id = graph.add_node("asset", data_source.name, source_kind="data_source")
        graph.add_edge(ds_id, llm_id, "can_influence")
        graph.add_edge(llm_id, ds_id, "can_read")
        if data_source.is_untrusted:
            retrieved_id = graph.add_node("entrypoint", "retrieved_content")
            graph.add_edge(retrieved_id, ds_id, "can_influence")
        for tool in surface.tools:
            if tool.can_egress:
                tool_id = graph.add_node("capability", tool.name, source_kind="tool")
                graph.add_edge(ds_id, tool_id, "can_influence")

    for server in surface.mcp_servers:
        server_id = graph.add_node("capability", server.name, source_kind="mcp_server")
        graph.add_edge(server_id, llm_id, "can_influence")
        if server.is_untrusted:
            mcp_id = graph.add_node("entrypoint", "mcp_response")
            graph.add_edge(mcp_id, server_id, "can_influence")
        for tool_name in server.allowed_tools:
            tool_id = graph.add_node("capability", tool_name, source_kind="tool")
            graph.add_edge(server_id, tool_id, "can_trigger")

    return graph
