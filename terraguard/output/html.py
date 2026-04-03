from html import escape

from terraguard.core.findings import ScanResult
from terraguard.output.markdown import render as render_markdown


def render(result: ScanResult) -> str:
    body = escape(render_markdown(result)).replace("\n", "<br>\n")
    return f"<!doctype html><html><head><title>TerraGuard Report</title></head><body>{body}</body></html>"

