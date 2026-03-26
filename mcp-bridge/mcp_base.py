#!/usr/bin/env python3
"""
Shared MCP stdio infrastructure for Kali bridge clients.
Provides: structured stdout writes, shutdown event, base method handlers,
and the stdin dispatch loop.
"""

import sys
import json
import threading
import datetime
import os
from concurrent.futures import ThreadPoolExecutor

_stdout_lock = threading.Lock()
_shutdown = threading.Event()


def log(msg, level="INFO", **kw):
    entry = {
        "ts":    datetime.datetime.utcnow().strftime('%H:%M:%S') + "Z",
        "level": level,
        "msg":   msg,
    }
    entry.update(kw)
    sys.stderr.write(json.dumps(entry) + "\n")
    sys.stderr.flush()


def send_response(req_id, result=None, error=None):
    response = {"jsonrpc": "2.0", "id": req_id}
    if error:
        response["error"] = error
    else:
        response["result"] = result
    with _stdout_lock:
        sys.stdout.write(json.dumps(response) + "\n")
        sys.stdout.flush()


def make_base_handler(server_info, tools):
    """
    Return a function that handles the boilerplate MCP methods:
    initialize, notifications/initialized, tools/list, shutdown, exit.

    Returns True when the method was handled (caller should return early).
    Returns False when the method is unknown to the base (caller handles it).
    """
    def handle(req):
        req_id = req.get("id")
        method = req.get("method")

        if method == "initialize":
            send_response(req_id, {
                "protocolVersion": "2024-11-05",
                "capabilities": {"tools": {"listChanged": False}},
                "serverInfo": server_info,
            })
            log(f"{server_info['name']} initialized")
            return True

        elif method == "notifications/initialized":
            log("Client ready")
            return True

        elif method == "tools/list":
            send_response(req_id, {"tools": tools})
            return True

        elif method == "shutdown":
            send_response(req_id, None)
            log("Shutdown requested")
            _shutdown.set()
            return True

        elif method == "exit":
            log("Exit received")
            _shutdown.set()
            return True

        return False

    return handle


def run_stdio_loop(handle_message_fn, server_name):
    """
    Main event loop.  Reads JSON-RPC lines from stdin and dispatches each
    to handle_message_fn via a bounded thread pool.  Exits cleanly when
    _shutdown is set (by the shutdown/exit handler in make_base_handler).
    """
    _max_workers = int(os.environ.get("MCP_WORKERS", "10"))
    executor = ThreadPoolExecutor(max_workers=_max_workers)
    log(f"{server_name} started")
    for line in sys.stdin:
        if _shutdown.is_set():
            break
        line = line.strip()
        if line:
            executor.submit(handle_message_fn, line)
    executor.shutdown(wait=True, cancel_futures=True)  # drain in-flight requests before exiting
