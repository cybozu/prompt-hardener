import json
from typing import Any, Dict, List

import boto3
from botocore.config import Config

from prompt_hardener.llm.types import LLMRequest, LLMResponse, LLMUsage
from prompt_hardener.utils import to_bedrock_message_format


class BedrockProvider:
    name = "bedrock"

    def _normalize_tools(self, tools: List[Dict[str, Any]]) -> Dict[str, Any]:
        normalized_tools = []
        for tool in tools or []:
            if "toolSpec" in tool:
                normalized_tools.append(tool)
                continue
            function = tool.get("function", {}) if isinstance(tool, dict) else {}
            normalized_tools.append(
                {
                    "toolSpec": {
                        "name": function.get("name"),
                        "description": function.get("description", ""),
                        "inputSchema": {
                            "json": function.get("parameters")
                            or {"type": "object", "properties": {}}
                        },
                    }
                }
            )
        return {"tools": normalized_tools}

    def _normalize_tool_calls(self, blocks: List[Any]):
        normalized = []
        for block in blocks or []:
            if not isinstance(block, dict) or "toolUse" not in block:
                continue
            tool_use = block["toolUse"] or {}
            normalized.append(
                {
                    "id": tool_use.get("toolUseId"),
                    "type": "function",
                    "function": {
                        "name": tool_use.get("name"),
                        "arguments": json.dumps(
                            tool_use.get("input"), ensure_ascii=False
                        ),
                    },
                }
            )
        return normalized or None

    def generate(self, request: LLMRequest) -> LLMResponse:
        mode = self._select_mode(request)
        if mode == "converse":
            return self._generate_converse(request)
        return self._generate_invoke_model(request)

    def _make_client(self, request: LLMRequest):
        session = (
            boto3.Session(profile_name=request.aws_profile)
            if request.aws_profile
            else boto3.Session()
        )
        kwargs: Dict[str, Any] = {"region_name": request.aws_region}
        if request.timeout_seconds is not None:
            kwargs["config"] = Config(
                read_timeout=request.timeout_seconds,
                connect_timeout=request.timeout_seconds,
            )
        return session.client("bedrock-runtime", **kwargs)

    def _select_mode(self, request: LLMRequest) -> str:
        metadata = request.metadata or {}
        if metadata.get("bedrock_mode") in ("invoke_model", "converse"):
            return metadata["bedrock_mode"]
        if request.tools or request.tool_choice or request.system_prompt is not None:
            return "converse"
        if request.messages and any(
            not isinstance(message.content, str) for message in request.messages
        ):
            return "converse"
        return "invoke_model"

    def _generate_invoke_model(self, request: LLMRequest) -> LLMResponse:
        client = self._make_client(request)
        payload: Dict[str, Any] = {
            "anthropic_version": "bedrock-2023-05-31",
            "messages": [
                {"role": message.role, "content": message.content}
                for message in request.messages
            ],
        }
        if request.temperature is not None:
            payload["temperature"] = request.temperature
        if request.max_output_tokens is not None:
            payload["max_tokens"] = request.max_output_tokens
        if request.stop:
            payload["stop_sequences"] = request.stop
        if request.system_prompt is not None:
            payload["system"] = request.system_prompt

        response = client.invoke_model(
            modelId=request.model,
            body=json.dumps(payload),
            contentType="application/json",
            accept="application/json",
        )
        raw_body = json.loads(response.get("body").read())
        text = self._extract_text_from_blocks(raw_body.get("content", []))
        usage = self._usage_from_body(raw_body)
        return LLMResponse(
            text=text,
            provider=self.name,
            model=request.model,
            finish_reason=raw_body.get("stop_reason"),
            usage=usage,
            raw=raw_body,
        )

    def _generate_converse(self, request: LLMRequest) -> LLMResponse:
        client = self._make_client(request)
        kwargs: Dict[str, Any] = {
            "modelId": request.model,
            "messages": to_bedrock_message_format(
                [
                    {"role": message.role, "content": message.content}
                    for message in request.messages
                ]
            ),
        }
        if request.system_prompt is not None:
            kwargs["system"] = [{"text": request.system_prompt}]
        inference: Dict[str, Any] = {}
        if request.temperature is not None:
            inference["temperature"] = request.temperature
        if request.max_output_tokens is not None:
            inference["maxTokens"] = request.max_output_tokens
        if request.stop:
            inference["stopSequences"] = request.stop
        if inference:
            kwargs["inferenceConfig"] = inference
        if request.tools:
            kwargs["toolConfig"] = self._normalize_tools(request.tools)

        response = client.converse(**kwargs)
        output = response.get("output", {}).get("message", {}).get("content", [])
        tool_calls = self._normalize_tool_calls(output)
        usage_data = response.get("usage") or {}
        usage = None
        if usage_data:
            usage = LLMUsage(
                input_tokens=usage_data.get("inputTokens"),
                output_tokens=usage_data.get("outputTokens"),
                total_tokens=usage_data.get("totalTokens"),
            )
        return LLMResponse(
            text=self._extract_text_from_blocks(output),
            provider=self.name,
            model=request.model,
            finish_reason=response.get("stopReason"),
            usage=usage,
            raw=response,
            tool_calls=tool_calls,
        )

    def _extract_text_from_blocks(self, blocks: List[Any]) -> str:
        parts = []
        for block in blocks or []:
            if isinstance(block, dict):
                if "text" in block:
                    parts.append(block["text"])
                elif "content" in block and isinstance(block["content"], str):
                    parts.append(block["content"])
        return "".join(parts).strip()

    def _usage_from_body(self, raw_body: Dict[str, Any]) -> LLMUsage:
        usage_data = raw_body.get("usage") or {}
        if not usage_data:
            return None
        return LLMUsage(
            input_tokens=usage_data.get("input_tokens")
            or usage_data.get("inputTokens"),
            output_tokens=usage_data.get("output_tokens")
            or usage_data.get("outputTokens"),
            total_tokens=usage_data.get("total_tokens")
            or usage_data.get("totalTokens"),
        )
