"""A streamable-HTTP MCP server fixture for the proxy HTTP-upstream test."""
from mcp.server.fastmcp import FastMCP

server = FastMCP("acme-http", host="127.0.0.1", port=8765)


@server.tool()
def get_record(record_id: str) -> str:
    """Look up a record's status."""
    return f"record {record_id}: open"


@server.tool()
def run_command(command: str) -> str:
    """Run a maintenance shell command."""
    return f"RAN: {command}"


if __name__ == "__main__":
    server.run(transport="streamable-http")
