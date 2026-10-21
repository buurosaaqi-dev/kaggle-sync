#!/usr/bin/env python3
"""Small OpenAI-compatible server for WhiteRabbitNeo on Kaggle GPUs."""

from __future__ import annotations

import asyncio
import gc
import json
import os
import re
import time
import uuid
from typing import Any

import torch
from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse, StreamingResponse
from transformers import AutoModelForCausalLM, AutoTokenizer, BitsAndBytesConfig
import uvicorn


MODEL_ID = os.environ.get("OPENCLAW_MODEL_ID", "WhiteRabbitNeo/WhiteRabbitNeo-13B-v1")
MODEL_ALIAS = os.environ.get("OPENCLAW_MODEL_ALIAS", "WhiteRabbitNeo-13B")
PORT = int(os.environ.get("OPENCLAW_MODEL_PORT", "8000"))
MAX_INPUT_TOKENS = int(os.environ.get("OPENCLAW_MODEL_MAX_INPUT", "3072"))
MAX_OUTPUT_TOKENS = int(os.environ.get("OPENCLAW_MODEL_MAX_OUTPUT", "1024"))
TOOL_PATTERN = re.compile(r"<tool_call>\s*(\{.*?\})\s*</tool_call>", re.DOTALL)

app = FastAPI(title="WhiteRabbitNeo OpenAI-Compatible API")
generation_lock = asyncio.Lock()


def gpu_memory_map() -> dict[int, str] | None:
    count = torch.cuda.device_count()
    if count == 0:
        return None
    result: dict[int, str] = {}
    for index in range(count):
        total_gib = torch.cuda.get_device_properties(index).total_memory / 1024**3
        result[index] = f"{max(4, int(total_gib * 0.82))}GiB"
    return result


quantization = BitsAndBytesConfig(
    load_in_4bit=True,
    bnb_4bit_quant_type="nf4",
    bnb_4bit_compute_dtype=torch.float16,
    bnb_4bit_use_double_quant=True,
)
tokenizer = AutoTokenizer.from_pretrained(MODEL_ID, trust_remote_code=True)
if tokenizer.pad_token_id is None:
    tokenizer.pad_token_id = tokenizer.eos_token_id
model = AutoModelForCausalLM.from_pretrained(
    MODEL_ID,
    quantization_config=quantization,
    device_map="auto",
    max_memory=gpu_memory_map(),
    torch_dtype=torch.float16,
    low_cpu_mem_usage=True,
    trust_remote_code=True,
)
model.eval()
print(f"model_ready={MODEL_ID} devices={model.hf_device_map}", flush=True)


def text_content(content: Any) -> str:
    if isinstance(content, str):
        return content
    if not isinstance(content, list):
        return json.dumps(content, ensure_ascii=False)
    pieces: list[str] = []
    for part in content:
        if isinstance(part, str):
            pieces.append(part)
        elif isinstance(part, dict) and isinstance(part.get("text"), str):
            pieces.append(part["text"])
    return "\n".join(pieces)


def render_prompt(messages: list[dict[str, Any]], tools: list[dict[str, Any]]) -> str:
    lines: list[str] = []
    if tools:
        compact_tools = [
            {
                "name": item.get("function", {}).get("name"),
                "description": item.get("function", {}).get("description", ""),
                "parameters": item.get("function", {}).get("parameters", {}),
            }
            for item in tools
            if item.get("type") == "function"
        ]
        lines.append(
            "SYSTEM: Available tools follow. To call one, output exactly "
            "<tool_call>{\"name\":\"tool_name\",\"arguments\":{...}}</tool_call>. "
            "Do not claim a tool succeeded before receiving its TOOL result.\n"
            + json.dumps(compact_tools, ensure_ascii=False, separators=(",", ":"))
        )
    for message in messages:
        role = str(message.get("role", "user")).lower()
        content = text_content(message.get("content", ""))
        if role == "system" or role == "developer":
            lines.append(f"SYSTEM: {content}")
        elif role == "assistant":
            lines.append(f"ASSISTANT: {content}")
            for call in message.get("tool_calls") or []:
                function = call.get("function", {})
                lines.append(
                    "ASSISTANT: <tool_call>"
                    + json.dumps(
                        {"name": function.get("name"), "arguments": function.get("arguments", "{}")},
                        ensure_ascii=False,
                    )
                    + "</tool_call>"
                )
        elif role == "tool":
            lines.append(f"TOOL {message.get('name', message.get('tool_call_id', 'result'))}: {content}")
        else:
            lines.append(f"USER: {content}")
    lines.append("ASSISTANT:")
    return "\n".join(lines)


def parse_tool_calls(text: str) -> tuple[str, list[dict[str, Any]]]:
    calls: list[dict[str, Any]] = []
    for match in TOOL_PATTERN.finditer(text):
        try:
            payload = json.loads(match.group(1))
            name = payload.get("name") or payload.get("function", {}).get("name")
            arguments = payload.get("arguments", payload.get("function", {}).get("arguments", {}))
            if not isinstance(name, str) or not name:
                continue
            if isinstance(arguments, str):
                try:
                    json.loads(arguments)
                    encoded_arguments = arguments
                except json.JSONDecodeError:
                    encoded_arguments = json.dumps({"input": arguments}, ensure_ascii=False)
            else:
                encoded_arguments = json.dumps(arguments, ensure_ascii=False)
            calls.append(
                {
                    "id": f"call_{uuid.uuid4().hex[:24]}",
                    "type": "function",
                    "function": {"name": name, "arguments": encoded_arguments},
                }
            )
        except (json.JSONDecodeError, AttributeError):
            continue
    content = TOOL_PATTERN.sub("", text).strip()
    return content, calls


def completion_chunks(completion_id: str, content: str, calls: list[dict[str, Any]], usage: dict[str, int]):
    created = int(time.time())
    first_delta: dict[str, Any] = {"role": "assistant"}
    if content:
        first_delta["content"] = content
    if calls:
        first_delta["tool_calls"] = [dict(call, index=index) for index, call in enumerate(calls)]
    first = {
        "id": completion_id,
        "object": "chat.completion.chunk",
        "created": created,
        "model": MODEL_ALIAS,
        "choices": [{"index": 0, "delta": first_delta, "finish_reason": None}],
    }
    final = {
        "id": completion_id,
        "object": "chat.completion.chunk",
        "created": created,
        "model": MODEL_ALIAS,
        "choices": [{"index": 0, "delta": {}, "finish_reason": "tool_calls" if calls else "stop"}],
        "usage": usage,
    }
    yield f"data: {json.dumps(first, ensure_ascii=False)}\n\n"
    yield f"data: {json.dumps(final, ensure_ascii=False)}\n\n"
    yield "data: [DONE]\n\n"


@app.get("/health")
async def health():
    return {"status": "ok", "model": MODEL_ALIAS, "gpus": torch.cuda.device_count()}


@app.get("/v1/models")
async def models():
    return {
        "object": "list",
        "data": [
            {"id": MODEL_ALIAS, "object": "model", "owned_by": "whiterabbit"},
            {"id": MODEL_ID, "object": "model", "owned_by": "whiterabbit"},
        ],
    }


@app.post("/v1/chat/completions")
async def chat_completions(request: Request):
    try:
        data = await request.json()
        prompt = render_prompt(data.get("messages") or [], data.get("tools") or [])
        requested_tokens = data.get("max_tokens", data.get("max_completion_tokens", 512))
        max_tokens = max(1, min(int(requested_tokens or 512), MAX_OUTPUT_TOKENS))
        temperature = float(data.get("temperature", 0.7) or 0)
        top_p = float(data.get("top_p", 0.95) or 0.95)

        async with generation_lock:
            inputs = tokenizer(
                prompt,
                return_tensors="pt",
                max_length=MAX_INPUT_TOKENS,
                truncation=True,
            ).to(model.device)
            input_tokens = int(inputs.input_ids.shape[1])
            generate_args: dict[str, Any] = {
                "max_new_tokens": max_tokens,
                "do_sample": temperature > 0,
                "top_p": top_p,
                "pad_token_id": tokenizer.pad_token_id,
                "eos_token_id": tokenizer.eos_token_id,
            }
            if temperature > 0:
                generate_args["temperature"] = temperature
            with torch.inference_mode():
                outputs = model.generate(**inputs, **generate_args)
            generated = outputs[0][input_tokens:]
            output_tokens = int(generated.shape[0])
            response_text = tokenizer.decode(generated, skip_special_tokens=True).strip()
            del inputs, outputs, generated
            torch.cuda.empty_cache()
            gc.collect()

        content, calls = parse_tool_calls(response_text)
        completion_id = f"chatcmpl-{uuid.uuid4().hex}"
        usage = {
            "prompt_tokens": input_tokens,
            "completion_tokens": output_tokens,
            "total_tokens": input_tokens + output_tokens,
        }
        if data.get("stream"):
            return StreamingResponse(
                completion_chunks(completion_id, content, calls, usage),
                media_type="text/event-stream",
            )
        message: dict[str, Any] = {"role": "assistant", "content": content or None}
        if calls:
            message["tool_calls"] = calls
        return {
            "id": completion_id,
            "object": "chat.completion",
            "created": int(time.time()),
            "model": MODEL_ALIAS,
            "choices": [
                {
                    "index": 0,
                    "message": message,
                    "finish_reason": "tool_calls" if calls else "stop",
                }
            ],
            "usage": usage,
        }
    except Exception as exc:
        torch.cuda.empty_cache()
        gc.collect()
        return JSONResponse(status_code=500, content={"error": {"message": str(exc), "type": type(exc).__name__}})


if __name__ == "__main__":
    uvicorn.run(app, host="127.0.0.1", port=PORT, log_level="info")
