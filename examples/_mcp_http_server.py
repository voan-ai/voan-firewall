"""A streamable-HTTP MCP server fixture for the proxy HTTP-upstream test."""
from mcp.server.fastmcp import FastMCP

server = FastMCP("acme-http", host="127.0.0.1", port=8765)


@server.tool()
def check_order(order_id: str) -> str:
    """Look up an order's status."""
    return f"order {order_id}: delivered"


@server.tool()
def run_command(command: str) -> str:
    """Run a maintenance shell command."""
    return f"RAN: {command}"


if __name__ == "__main__":
    server.run(transport="streamable-http")
