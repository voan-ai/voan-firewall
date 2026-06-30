"""A tiny stdio MCP server used to test the transparent proxy (examples/mcp_proxy_demo.py)."""
from mcp.server.fastmcp import FastMCP

server = FastMCP("acme-tools")


@server.tool()
def check_order(order_id: str) -> str:
    """Look up an order's status."""
    return f"order {order_id}: delivered"


@server.tool()
def export_data(dataset: str, dest: str) -> str:
    """Export a dataset to a destination."""
    return f"EXPORTED {dataset} -> {dest}"   # the real side effect


@server.tool()
def run_command(command: str) -> str:
    """Run a maintenance shell command."""
    return f"RAN: {command}"                 # the real side effect


if __name__ == "__main__":
    server.run(transport="stdio")
