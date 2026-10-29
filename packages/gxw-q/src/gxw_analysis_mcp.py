"""Local stdio adapter with operator-owned disclosure and no caller overrides."""
from __future__ import annotations

import argparse
import asyncio
import io
import sys

import gxw_analysis_service as core

FRAME_LIMIT = 16 * 1024


def create_server(service):
    # Optional SDK stays outside the parser's default dependency surface.
    from mcp.server.lowlevel import Server
    import mcp.types as types

    names = {"inventory": "inventory", "inspect": "inspect", "reference_query": "query", "compare": "compare"}
    detail = service.registry.disclosure == "authorized-detail"
    tools = []
    for name, operation in names.items():
        properties = {"project_id": {"type": "string", "pattern": core.ID.pattern, "maxLength": 48},
                      "offset": {"type": "integer", "minimum": 0, "maximum": 1000000, "default": 0}}
        required = ["project_id"]
        if operation == "compare":
            properties["right_id"] = properties["project_id"].copy()
            required.append("right_id")
        if operation == "query":
            properties["device"] = {"type": "string", "maxLength": 64}
            required.append("device")
        tools.append(types.Tool(name=name, description={
            "inventory": "등록 프로젝트의 프로그램 목록을 가명으로 조회합니다.",
            "inspect": ("등록 프로젝트의 부분 분석과 운영자가 허용한 세부 관측을 조회합니다." if detail
                        else "등록 프로젝트의 지원 범위와 부분 분석 개수를 조회합니다."),
            "reference_query": ("직접 디바이스 주소와 운영자가 허용한 관련 관측을 조회합니다." if detail
                                else "직접 디바이스 주소의 관측 사용처를 가명으로 조회합니다."),
            "compare": "등록 프로젝트 두 개의 바이트와 지원 관측 차이를 조회합니다."}[name],
            inputSchema={"type": "object", "properties": properties, "required": required, "additionalProperties": False},
            annotations=types.ToolAnnotations(readOnlyHint=True, destructiveHint=False,
                                             idempotentHint=True, openWorldHint=False)))

    async def list_tools(ctx, params):
        return types.ListToolsResult(tools=tools)

    async def call_tool(ctx, params):
        try:
            if params.name not in names or type(params.arguments) is not dict:
                service.reject_call()
                core.reject("INVALID_ARGUMENTS")
            tool = next(t for t in tools if t.name == params.name)
            args = params.arguments
            if args.keys() - tool.input_schema["properties"].keys() or not set(tool.input_schema["required"]) <= args.keys():
                service.reject_call()
                core.reject("INVALID_ARGUMENTS")
            result = await service.execute(names[params.name], **args)
            return types.CallToolResult(content=[types.TextContent(type="text", text=core.engine.canonical_json(result))],
                                        structuredContent=result)
        except core.ServiceError as exc:
            return types.CallToolResult(content=[types.TextContent(type="text", text=str(exc))], isError=True)
        except (TypeError, ValueError):
            return types.CallToolResult(content=[types.TextContent(type="text", text="INVALID_ARGUMENTS")], isError=True)
        except Exception:
            return types.CallToolResult(content=[types.TextContent(type="text", text="REQUEST_REJECTED")], isError=True)

    return Server("gxw-readonly", version="1", on_list_tools=list_tools, on_call_tool=call_tool,
                  get_tool_input_schema=lambda name: next((t.input_schema for t in tools if t.name == name), None))


class BoundedInput:
    def __init__(self, stream):
        self.stream = stream

    def __aiter__(self):
        return self

    async def __anext__(self):
        import anyio
        data = await anyio.to_thread.run_sync(self.stream.readline, FRAME_LIMIT + 1, abandon_on_cancel=True)
        if not data:
            raise StopAsyncIteration
        if len(data) > FRAME_LIMIT or not data.endswith(b"\n"):
            raise ValueError("FRAME_LIMIT")
        return data.decode("utf-8", errors="strict")


async def serve(service):
    import anyio
    import logging
    from mcp.server.stdio import stdio_server
    # SDK diagnostic tracebacks may contain installation paths. The explicit
    # minimal local audit is the service's only logging channel.
    logging.disable(logging.CRITICAL)
    server = create_server(service)
    incoming = BoundedInput(sys.stdin.buffer)
    outgoing = anyio.wrap_file(io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8", write_through=True))
    async with stdio_server(stdin=incoming, stdout=outgoing) as (read, write):
        await server.run(read, write, server.create_initialization_options())


def main(argv=None):
    parser = core.RegisteredArgumentParser(description="등록한 합성 GXW에 로컬 읽기 전용 MCP를 제공합니다.")
    parser.add_argument("--config", required=True)
    parser.add_argument("--config-sha256", required=True)
    service = None
    try:
        args = parser.parse_args(argv)
        service = core.ReadService(core.Registry.load(args.config, args.config_sha256))
        asyncio.run(serve(service))
        service.close()
        service = None
        return 0
    except (core.ServiceError, ImportError):
        print("시작 설정 또는 선택 설치 의존성을 확인하십시오.", file=sys.stderr)
        return 2
    except Exception:
        print("MCP 연결을 종료했습니다.", file=sys.stderr)
        return 2
    finally:
        if service is not None:
            try:
                service.close()
            except core.ServiceError:
                pass


if __name__ == "__main__":
    raise SystemExit(main())
