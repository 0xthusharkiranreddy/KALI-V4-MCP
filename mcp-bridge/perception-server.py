#!/usr/bin/env python3
"""
Perception server — Flask + Playwright running on Kali :5000
Returns structured DOM state instead of raw screenshots.
Screenshots only included when CAPTCHA is detected.

Deploy: copy to /home/kali/perception-server.py on Kali VM
Run:    nohup /opt/perception-venv/bin/python3 /home/kali/perception-server.py > /tmp/perception.log 2>&1 &
"""

import asyncio, base64, hashlib, threading, time
from flask import Flask, request, jsonify

app = Flask(__name__)

_browser = None
_context = None
_page    = None
_pw      = None
_loop    = None
_network_log = []
_proxy_host  = None
_proxy_port  = None

CAPTCHA_SIGNALS = [
    'iframe[src*="hcaptcha.com"]',
    'iframe[src*="recaptcha"]',
    '.g-recaptcha',
    '#h-captcha',
    '[data-sitekey]',
    # Cloudflare Turnstile
    'iframe[src*="challenges.cloudflare.com"]',
    '.cf-turnstile',
    '[class*="cf-chl"]',
    '[id*="cf-chl"]',
    '[id*="turnstile"]',
]


def run_async(coro, timeout=30):
    future = asyncio.run_coroutine_threadsafe(coro, _loop)
    return future.result(timeout=timeout)


async def _on_response(response):
    global _network_log
    req = response.request
    if req.resource_type not in ('xhr', 'fetch', 'document'):
        return
    entry = {'url': req.url, 'method': req.method,
              'status': response.status, 'resource_type': req.resource_type,
              'response_body': None}
    try:
        entry['response_body'] = await response.text()
    except Exception:
        pass
    _network_log.append(entry)
    if len(_network_log) > 20:
        _network_log = _network_log[-20:]


async def _ensure_browser():
    global _browser, _context, _page, _pw
    if _page is not None:
        return
    from playwright.async_api import async_playwright
    _pw = await async_playwright().start()
    kw = dict(
        headless=False,
        args=['--no-sandbox', '--disable-dev-shm-usage'],
        env={'DISPLAY': ':0', 'XAUTHORITY': '/home/kali/.Xauthority'},
    )
    if _proxy_host and _proxy_port:
        kw['proxy'] = {'server': f'http://{_proxy_host}:{_proxy_port}'}
    _browser = await _pw.chromium.launch(**kw)
    _context = await _browser.new_context()
    _context.on('response', _on_response)
    _page = await _context.new_page()


async def _get_state():
    url   = _page.url
    title = await _page.title()

    forms = await _page.evaluate('''() => Array.from(document.querySelectorAll("form")).map(f => ({
        id: f.id || null, action: f.action || null,
        method: (f.method || "get").toUpperCase(),
        inputs: Array.from(f.querySelectorAll("input,select,textarea")).map(i => ({
            name: i.name || i.id || null,
            type: i.type || i.tagName.toLowerCase(),
            placeholder: i.placeholder || null,
            value: i.type === "password" ? "***" : (i.value || null),
            required: i.required || false,
        })).filter(i => i.type !== "hidden" || i.name),
    }))''')

    buttons = await _page.evaluate("""() => Array.from(document.querySelectorAll(
        "button, input[type='submit'], input[type='button']"
    )).slice(0,20).map(b => ({
        text: (b.textContent||"").trim() || b.value || null,
        selector: b.id ? "#"+b.id : b.tagName.toLowerCase()+(b.type ? "[type='"+b.type+"']" : ""),
        type: b.type || null,
    }))""")

    links = await _page.evaluate('''() => Array.from(document.querySelectorAll("a[href]")).slice(0,30).map(a => ({
        text: (a.textContent||"").trim() || null, href: a.href || null,
    })).filter(l => l.text && l.href && !l.href.startsWith("javascript:"))''')

    errors = await _page.evaluate("""() => {
        const sels = [".error",".alert-danger",".alert-error","[role='alert']",
                      ".invalid-feedback",".error-message","#error"];
        const out = [];
        sels.forEach(s => document.querySelectorAll(s).forEach(el => {
            const t = (el.textContent||"").trim(); if (t) out.push(t);
        }));
        return [...new Set(out)];
    }""")

    alerts = await _page.evaluate("""() => {
        const sels = [".alert-success",".alert-info",".notice",".flash"];
        const out = [];
        sels.forEach(s => document.querySelectorAll(s).forEach(el => {
            const t = (el.textContent||"").trim(); if (t) out.push(t);
        }));
        return [...new Set(out)];
    }""")

    content = await _page.content()
    state_hash = hashlib.md5(content.encode()).hexdigest()[:8]

    captcha = None
    screenshot_b64 = None
    for signal in CAPTCHA_SIGNALS:
        try:
            el = await _page.query_selector(signal)
            if el:
                captcha = ('hcaptcha' if 'hcaptcha' in signal
                           else 'recaptcha' if 'recaptcha' in signal
                           else 'unknown')
                break
        except Exception:
            pass
    if captcha:
        screenshot_b64 = base64.b64encode(await _page.screenshot()).decode()

    return {'url': url, 'title': title, 'forms': forms, 'buttons': buttons,
            'links': links, 'errors': errors, 'alerts': alerts,
            'captcha': captcha, 'state_hash': state_hash, 'screenshot': screenshot_b64}


# ── Routes ──────────────────────────────────────────────────────────────────────

@app.route('/health')
def health():
    return jsonify({'status': 'ok', 'browser_active': _page is not None})


@app.route('/navigate', methods=['POST'])
def navigate():
    data = request.json or {}
    url = data.get('url')
    if not url:
        return jsonify({'error': 'url required'}), 400
    proxy_p = data.get('proxy_port')
    async def _nav():
        global _proxy_port
        if proxy_p:
            _proxy_port = proxy_p
        await _ensure_browser()
        await _page.goto(url, wait_until='load', timeout=60000)
        return await _get_state()
    try:
        return jsonify(run_async(_nav(), timeout=35))
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/click', methods=['POST'])
def click():
    data = request.json or {}
    selector, x, y = data.get('selector'), data.get('x'), data.get('y')
    async def _click():
        if selector:
            await _page.click(selector, timeout=10000)
        elif x is not None and y is not None:
            await _page.mouse.click(float(x), float(y))
        else:
            return {'error': 'Need selector or x,y'}
        try:
            await _page.wait_for_load_state('networkidle', timeout=8000)
        except Exception:
            pass
        return await _get_state()
    try:
        return jsonify(run_async(_click()))
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/type', methods=['POST'])
def type_text():
    data = request.json or {}
    selector, text = data.get('selector'), data.get('text', '')
    async def _type():
        if selector:
            await _page.fill(selector, text)
        else:
            await _page.keyboard.type(text)
        return await _get_state()
    try:
        return jsonify(run_async(_type()))
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/state')
def get_state():
    async def _s():
        return await _get_state()
    try:
        return jsonify(run_async(_s()))
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/wait', methods=['POST'])
def wait_for():
    """
    Wait for a URL pattern or CSS selector to appear, then return page state.
    Body: { condition: "https://..." | "css selector", timeout: seconds (default 10) }
    """
    data = request.json or {}
    condition = data.get('condition', '')
    timeout_s  = int(data.get('timeout', 10))
    timeout_ms = timeout_s * 1000
    if not condition:
        return jsonify({'error': 'condition required (URL pattern or CSS selector)'}), 400
    async def _wait():
        if condition.startswith('http'):
            await _page.wait_for_url(condition, timeout=timeout_ms)
        else:
            await _page.wait_for_selector(condition, state='visible', timeout=timeout_ms)
        return await _get_state()
    try:
        return jsonify(run_async(_wait(), timeout=timeout_s + 5))
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/screenshot')
def screenshot():
    async def _shot():
        return base64.b64encode(await _page.screenshot()).decode()
    try:
        return jsonify({'screenshot': run_async(_shot())})
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/eval', methods=['POST'])
def eval_js():
    data = request.json or {}
    js = data.get('js', '')
    async def _eval():
        return await _page.evaluate(js)
    try:
        return jsonify({'result': run_async(_eval())})
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/network')
def get_network():
    return jsonify({'requests': _network_log})


@app.route('/proxy', methods=['POST'])
def set_proxy():
    global _browser, _context, _page, _pw, _proxy_host, _proxy_port
    data = request.json or {}
    enabled = data.get('enabled', False)
    host = data.get('host', '127.0.0.1')
    port = data.get('port', 8080)
    async def _reopen():
        global _browser, _context, _page, _pw
        for obj in (_page, _context, _browser):
            if obj:
                try:
                    await obj.close()
                except Exception:
                    pass
        if _pw:
            try:
                await _pw.stop()
            except Exception:
                pass
        _page = _context = _browser = _pw = None
    try:
        run_async(_reopen())
        _proxy_host = host if enabled else None
        _proxy_port = port if enabled else None
        return jsonify({'status': 'proxy configured', 'enabled': enabled,
                        'host': _proxy_host, 'port': _proxy_port})
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/close', methods=['POST'])
def close_browser():
    global _browser, _context, _page, _pw
    async def _close():
        global _browser, _context, _page, _pw
        for obj in (_page, _context, _browser):
            if obj:
                try:
                    await obj.close()
                except Exception:
                    pass
        if _pw:
            try:
                await _pw.stop()
            except Exception:
                pass
        _page = _context = _browser = _pw = None
        return {'status': 'closed'}
    try:
        return jsonify(run_async(_close()))
    except Exception as e:
        return jsonify({'error': str(e)}), 500


# ── Startup ──────────────────────────────────────────────────────────────────────

def _start_loop():
    global _loop
    _loop = asyncio.new_event_loop()
    asyncio.set_event_loop(_loop)
    _loop.run_forever()


if __name__ == '__main__':
    t = threading.Thread(target=_start_loop, daemon=True)
    t.start()
    time.sleep(0.3)
    print('Perception server starting on :5000 ...', flush=True)
    app.run(host='0.0.0.0', port=5000, threaded=True)
