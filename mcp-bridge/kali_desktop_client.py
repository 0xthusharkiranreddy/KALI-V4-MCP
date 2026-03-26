#!/usr/bin/env python3
"""
MCP stdio server for Kali Desktop Control Bridge — v2.
Provides full GUI desktop control: screenshot (returns image), click, type, key, scroll, drag, run apps.
"""

import json
import os
import requests
from mcp_base import log, send_response, make_base_handler, run_stdio_loop

BRIDGE_URL = "http://localhost:3002/v1/tools/execute"

# Convert ms timeout from env to seconds for requests library
COMMAND_TIMEOUT = int(os.environ.get("COMMAND_TIMEOUT", "3600000")) / 1000

TOOLS = [
    {
        "name": "desktop_screenshot",
        "description": "Take a screenshot of the Kali VM desktop and return it as an image. Always call this to see the current state before deciding where to click.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "region": {
                    "type": "string",
                    "description": "Optional: capture a specific region as 'x,y,width,height', e.g. '100,200,800,600'. Omit for full screen."
                }
            }
        }
    },
    {
        "name": "desktop_move",
        "description": "Move the mouse cursor to coordinates on the Kali desktop (does not click).",
        "inputSchema": {
            "type": "object",
            "properties": {
                "x": {"type": "integer", "description": "X coordinate (pixels from left)"},
                "y": {"type": "integer", "description": "Y coordinate (pixels from top)"}
            },
            "required": ["x", "y"]
        }
    },
    {
        "name": "desktop_click",
        "description": "Move mouse to coordinates and click. Takes a screenshot first if you need to find the target.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "x": {"type": "integer", "description": "X coordinate"},
                "y": {"type": "integer", "description": "Y coordinate"},
                "button": {"type": "integer", "description": "Mouse button: 1=left (default), 2=middle, 3=right"}
            },
            "required": ["x", "y"]
        }
    },
    {
        "name": "desktop_double_click",
        "description": "Double-click at specified coordinates (e.g. to open a file or select a word).",
        "inputSchema": {
            "type": "object",
            "properties": {
                "x": {"type": "integer"},
                "y": {"type": "integer"}
            },
            "required": ["x", "y"]
        }
    },
    {
        "name": "desktop_right_click",
        "description": "Right-click at specified coordinates to open context menus.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "x": {"type": "integer"},
                "y": {"type": "integer"}
            },
            "required": ["x", "y"]
        }
    },
    {
        "name": "desktop_type",
        "description": "Type text at the currently focused input. Use desktop_click first to focus an input field. Supports all Unicode characters.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "text": {"type": "string", "description": "Text to type"},
                "delay": {"type": "integer", "description": "Delay between keystrokes in milliseconds. Default: 20"}
            },
            "required": ["text"]
        }
    },
    {
        "name": "desktop_key",
        "description": "Press a keyboard key or combination. Examples: 'Return', 'ctrl+c', 'ctrl+v', 'ctrl+shift+i', 'ctrl+l', 'Escape', 'Tab', 'super', 'alt+F4', 'ctrl+a'",
        "inputSchema": {
            "type": "object",
            "properties": {
                "keys": {"type": "string", "description": "Key name or combo, e.g. 'Return', 'ctrl+c', 'ctrl+shift+i'"}
            },
            "required": ["keys"]
        }
    },
    {
        "name": "desktop_scroll",
        "description": "Scroll up or down at specified coordinates.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "x": {"type": "integer", "description": "X coordinate to scroll at"},
                "y": {"type": "integer", "description": "Y coordinate to scroll at"},
                "direction": {"type": "string", "enum": ["up", "down"], "description": "Scroll direction"},
                "amount": {"type": "integer", "description": "Number of scroll clicks. Default: 3"}
            },
            "required": ["x", "y", "direction"]
        }
    },
    {
        "name": "desktop_drag",
        "description": "Click and drag from (x1,y1) to (x2,y2). Useful for sliders, selecting text, moving windows.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "x1": {"type": "integer", "description": "Start X"},
                "y1": {"type": "integer", "description": "Start Y"},
                "x2": {"type": "integer", "description": "End X"},
                "y2": {"type": "integer", "description": "End Y"}
            },
            "required": ["x1", "y1", "x2", "y2"]
        }
    },
    {
        "name": "desktop_run",
        "description": "Launch an application on the Kali desktop. The app opens in the GUI and you can see it in VirtualBox. Examples: 'firefox', 'firefox https://example.com', 'burpsuite', 'code /path/to/project', 'xterm', 'mousepad /etc/hosts'",
        "inputSchema": {
            "type": "object",
            "properties": {
                "app_command": {"type": "string", "description": "Application command to launch, e.g. 'firefox https://target.com'"}
            },
            "required": ["app_command"]
        }
    },
    {
        "name": "desktop_get_window_list",
        "description": "List all open windows on the Kali desktop with their window IDs and titles.",
        "inputSchema": {
            "type": "object",
            "properties": {}
        }
    },
    {
        "name": "desktop_focus_window",
        "description": "Bring a window to the foreground and focus it by window ID (from desktop_get_window_list).",
        "inputSchema": {
            "type": "object",
            "properties": {
                "window_id": {"type": "string", "description": "Window ID from desktop_get_window_list"}
            },
            "required": ["window_id"]
        }
    },
    {
        "name": "desktop_get_screen_size",
        "description": "Get the screen dimensions of the Kali desktop (width x height in pixels).",
        "inputSchema": {
            "type": "object",
            "properties": {}
        }
    },
    {
        "name": "desktop_get_cursor_pos",
        "description": "Get the current mouse cursor position on the Kali desktop.",
        "inputSchema": {
            "type": "object",
            "properties": {}
        }
    },

    # ── Perception / browser tools ────────────────────────────────────────────
    {
        "name": "browser_navigate",
        "description": (
            "Navigate the persistent Playwright browser to a URL and return structured page state: "
            "url, title, forms (with inputs), buttons, links, errors, alerts, state_hash. "
            "NO screenshot is returned unless a CAPTCHA is detected. "
            "Optional proxy_port routes traffic through Burp (e.g. 8080)."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "url": {"type": "string", "description": "URL to navigate to"},
                "proxy_port": {"type": "integer", "description": "Optional Burp proxy port (e.g. 8080)"}
            },
            "required": ["url"]
        }
    },
    {
        "name": "browser_click",
        "description": (
            "Click an element in the Playwright browser by CSS selector or coordinates. "
            "Returns updated structured page state. Screenshot included only if CAPTCHA detected."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "selector": {"type": "string", "description": "CSS selector, e.g. 'button[type=submit]', '#login-btn'"},
                "x": {"type": "number", "description": "X coordinate (use instead of selector for pixel clicks)"},
                "y": {"type": "number", "description": "Y coordinate"}
            }
        }
    },
    {
        "name": "browser_type",
        "description": (
            "Fill a form field in the Playwright browser. "
            "Uses selector to target the field and fills it (replaces existing content). "
            "Returns updated structured page state."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "selector": {"type": "string", "description": "CSS selector for the input, e.g. '#username', 'input[name=email]'"},
                "text": {"type": "string", "description": "Text to fill into the field"}
            },
            "required": ["text"]
        }
    },
    {
        "name": "browser_get_state",
        "description": (
            "Get the current structured state of the Playwright browser page without any interaction. "
            "Returns url, title, forms, buttons, links, errors, alerts, state_hash. "
            "Use after user solves a CAPTCHA to detect when the page has progressed."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {}
        }
    },
    {
        "name": "browser_screenshot",
        "description": (
            "Take an explicit screenshot of the current Playwright browser page and return it as an image. "
            "Only use this when you genuinely need to see the visual layout. "
            "For normal state observation, use browser_get_state instead."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {}
        }
    },
    {
        "name": "browser_eval",
        "description": (
            "Evaluate arbitrary JavaScript in the Playwright browser page context and return the result. "
            "Useful for extracting data, checking JS variables, or manipulating the DOM."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "js": {"type": "string", "description": "JavaScript expression to evaluate, e.g. 'document.cookie'"}
            },
            "required": ["js"]
        }
    },
    {
        "name": "browser_get_network",
        "description": (
            "Return the last 20 XHR/fetch/document network requests captured by the Playwright browser. "
            "Includes URL, method, status code, and response body. Critical for API endpoint discovery."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {}
        }
    },
    {
        "name": "browser_set_proxy",
        "description": (
            "Enable or disable routing all Playwright browser traffic through a proxy (e.g. Burp Suite). "
            "When enabled, restarts the browser with proxy settings. "
            "Burp must be running on Kali at the given host:port."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "enabled": {"type": "boolean", "description": "True to enable proxy, False to disable"},
                "host": {"type": "string", "description": "Proxy host, default '127.0.0.1'"},
                "port": {"type": "integer", "description": "Proxy port, default 8080"}
            },
            "required": ["enabled"]
        }
    },
    {
        "name": "browser_close",
        "description": "Close the persistent Playwright browser. Next browser_navigate call will open a fresh one.",
        "inputSchema": {
            "type": "object",
            "properties": {}
        }
    }
]

SERVER_INFO = {"name": "kali-desktop-bridge", "version": "2.0.0"}
_handle_base = make_base_handler(SERVER_INFO, TOOLS)


def _safe_args(args):
    out = {}
    for k, v in args.items():
        if k in ('text', 'js'):
            out[k] = str(v)[:40] + '...' if len(str(v)) > 40 else v
        else:
            out[k] = v
    return out


def call_tool(tool_name, arguments):
    resp = requests.post(BRIDGE_URL, json={
        "tool_name": tool_name,
        "arguments": arguments
    }, timeout=(5, COMMAND_TIMEOUT))

    if resp.status_code != 200:
        raise Exception(f"Bridge returned HTTP {resp.status_code}: {resp.text}")

    data = resp.json()

    if not data.get("success"):
        raise Exception(data.get("error", "Unknown error from bridge"))

    # Explicit screenshot tools return image only
    if data.get("isImage"):
        return {
            "content": [
                {
                    "type": "image",
                    "data": data["data"],
                    "mimeType": data.get("mimeType", "image/png")
                }
            ]
        }

    # Browser perception tools: structured state (text) + optional CAPTCHA screenshot
    if data.get("isBrowser"):
        content = [{"type": "text", "text": data.get("result", "")}]
        if data.get("screenshot"):
            content.append({
                "type": "image",
                "data": data["screenshot"],
                "mimeType": "image/png"
            })
        return {"content": content}

    # All other desktop tools: plain text
    return {
        "content": [
            {
                "type": "text",
                "text": data.get("result", "")
            }
        ]
    }


def handle_message(line):
    try:
        req = json.loads(line)
    except json.JSONDecodeError:
        return

    req_id = req.get("id")
    method = req.get("method")
    params = req.get("params", {})

    if _handle_base(req):
        return

    if method == "tools/call":
        tool_name = params.get("name")
        arguments = params.get("arguments", {})
        log(f"Calling {tool_name} args={_safe_args(arguments)}")
        try:
            result = call_tool(tool_name, arguments)
            send_response(req_id, result)
        except Exception as e:
            send_response(req_id, error={"code": -32000, "message": str(e)})

    else:
        if req_id is not None:
            send_response(req_id, error={"code": -32601, "message": f"Method not found: {method}"})


def main():
    run_stdio_loop(handle_message, "kali-desktop-bridge")


if __name__ == "__main__":
    main()
