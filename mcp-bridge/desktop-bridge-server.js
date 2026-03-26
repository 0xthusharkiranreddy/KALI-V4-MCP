const express = require('express');
const cors = require('cors');
const { spawn } = require('child_process');

const app = express();
app.use(cors());
app.use(express.json({ limit: '50mb' }));

const PORT = process.env.DESKTOP_PORT || 3002;
const COMMAND_TIMEOUT = parseInt(process.env.COMMAND_TIMEOUT) || 3600000;
const SSH_POOL_SIZE = parseInt(process.env.SSH_POOL_SIZE) || 5;
const KALI_PORT = parseInt(process.env.KALI_PORT) || 22;
const DISPLAY_PREFIX = 'DISPLAY=:0 XAUTHORITY=/var/run/lightdm/root/:0';
const PERCEPTION_PORT = 5000;
const VBOXMANAGE = process.env.VBOXMANAGE || 'C:\\Program Files\\Oracle\\VirtualBox\\VBoxManage.exe';
const VBOX_VM = process.env.VBOX_VM || 'kali-linux-2025.4-virtualbox-amd64';
const SHOT_TMP = process.env.SHOT_TMP || 'C:\\Users\\thiru\\AppData\\Local\\Temp\\_vbox_shot.png';

// ─── Structured logging ────────────────────────────────────────────────────────
function log(level, event, extra = {}) {
  process.stdout.write(JSON.stringify({ ts: new Date().toISOString(), level, event, ...extra }) + '\n');
}

// ─── SSH connection pool ───────────────────────────────────────────────────────
let poolIdx = 0;
function getSocketPath() {
  const idx = (poolIdx % SSH_POOL_SIZE) + 1; // 1-indexed
  poolIdx = (poolIdx + 1) % SSH_POOL_SIZE;
  return `/tmp/ssh_mux_${process.env.KALI_HOST}_${idx}`;
}

async function executeKaliCommand(command) {
  return new Promise((resolve, reject) => {
    const socketPath = getSocketPath();
    const b64cmd = Buffer.from(command).toString('base64');
    const sshKey = process.env.SSH_KEY || '/root/.ssh/id_ed25519';
    const sshCmd =
      `ssh -i "${sshKey}" -p ${KALI_PORT} ` +
      `-o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null ` +
      `-o ControlMaster=auto -o ControlPath=${socketPath} -o ControlPersist=1h ` +
      `${process.env.KALI_USERNAME}@${process.env.KALI_HOST} ` +
      `'bash -c "$(echo ${b64cmd} | base64 -d)"'`;

    // Direct SSH — no docker exec relay
    const dockerExec = spawn('sh', ['-c', sshCmd]);

    let stdoutChunks = [];
    let stderr = '';

    const timer = setTimeout(() => {
      dockerExec.kill();
      reject(new Error(`Command timed out after ${COMMAND_TIMEOUT / 1000}s`));
    }, COMMAND_TIMEOUT);

    dockerExec.stdout.on('data', (data) => { stdoutChunks.push(data); });
    dockerExec.stderr.on('data', (data) => { stderr += data.toString(); });

    dockerExec.on('close', (code) => {
      clearTimeout(timer);
      const stdout = Buffer.concat(stdoutChunks);
      resolve({ stdout, stderr, code });
    });

    dockerExec.on('error', (err) => {
      clearTimeout(timer);
      reject(err);
    });
  });
}

// ─── VBoxManage screenshot (zero X11 involvement — no display freeze) ─────────
const fs = require('fs');
async function takeVBoxScreenshot(region) {
  return new Promise((resolve, reject) => {
    const proc = spawn(VBOXMANAGE, ['controlvm', VBOX_VM, 'screenshotpng', SHOT_TMP]);
    proc.on('close', (code) => {
      if (code !== 0) return reject(new Error(`VBoxManage exited ${code}`));
      try {
        let img = fs.readFileSync(SHOT_TMP);
        if (region) {
          // crop handled after reading — use sharp or return full and let client crop
          // For now return full image; region crop via ffmpeg on Kali would defeat the purpose
          // Return full frame and note region in metadata — client can crop if needed
        }
        resolve(img.toString('base64'));
      } catch (e) {
        reject(e);
      }
    });
    proc.on('error', reject);
  });
}

// ─── Perception server helpers ────────────────────────────────────────────────

let perceptionReady = false;
let perceptionStarting = false;

async function ensurePerceptionServer() {
  if (perceptionReady) return;

  if (perceptionStarting) {
    // Another call is already starting the server — wait up to 10s
    const deadline = Date.now() + 10000;
    while (perceptionStarting && Date.now() < deadline) {
      await new Promise(r => setTimeout(r, 200));
    }
    return;
  }

  perceptionStarting = true;
  try {
    const check = await executeKaliCommand(
      `curl -sf -m 5 http://localhost:${PERCEPTION_PORT}/health && echo ok`
    );
    if (check.stdout.toString().includes('ok')) {
      perceptionReady = true;
      return;
    }
    // Not running — start it and verify it actually responds (up to 15s)
    await executeKaliCommand(
      `nohup /opt/perception-venv/bin/python3 /home/kali/perception-server.py > /tmp/perception.log 2>&1 &`
    );
    const verify = await executeKaliCommand(
      `for i in 1 2 3 4 5; do curl -sf -m 5 http://localhost:${PERCEPTION_PORT}/health && echo ok && break || sleep 3; done`
    );
    if (!verify.stdout.toString().includes('ok')) {
      throw new Error('Perception server failed to start — check /tmp/perception.log on Kali');
    }
    perceptionReady = true;
  } finally {
    perceptionStarting = false;
  }
}

async function perceptionCall(method, endpoint, body) {
  await ensurePerceptionServer();
  let cmd;
  if (method === 'GET') {
    cmd = `curl -s http://localhost:${PERCEPTION_PORT}${endpoint}`;
  } else {
    const b64 = Buffer.from(JSON.stringify(body || {})).toString('base64');
    cmd = `echo ${b64} | base64 -d | curl -s -X POST http://localhost:${PERCEPTION_PORT}${endpoint} -H "Content-Type: application/json" --data-binary @-`;
  }
  const result = await executeKaliCommand(cmd);
  const text = result.stdout.toString('utf8').trim();
  if (!text) throw new Error(`Perception server returned empty response. stderr: ${result.stderr}`);
  try {
    return JSON.parse(text);
  } catch (e) {
    throw new Error(`Perception server returned invalid JSON: ${text.slice(0, 200)}`);
  }
}

// ─── Health ───────────────────────────────────────────────────────────────────

app.get('/health', (req, res) => {
  res.json({ status: 'ok', service: 'desktop-bridge' });
});

app.post('/v1/tools/execute', async (req, res) => {
  const { tool_name, arguments: args = {} } = req.body;

  try {
    let command = '';
    let isScreenshot = false;

    switch (tool_name) {

      case 'desktop_screenshot': {
        try {
          const base64 = await takeVBoxScreenshot(args.region || '');
          res.json({ success: true, isImage: true, data: base64, mimeType: 'image/png' });
        } catch (e) {
          res.status(500).json({ success: false, error: e.message });
        }
        return;
      }

      case 'desktop_move': {
        command = `${DISPLAY_PREFIX} xdotool mousemove ${args.x} ${args.y} && echo "moved to ${args.x},${args.y}"`;
        break;
      }

      case 'desktop_click': {
        const btn = args.button || 1;
        command = `${DISPLAY_PREFIX} xdotool mousemove ${args.x} ${args.y} click ${btn} && echo "clicked ${args.x},${args.y} btn=${btn}"`;
        break;
      }

      case 'desktop_double_click': {
        command = `${DISPLAY_PREFIX} xdotool mousemove ${args.x} ${args.y} click --repeat 2 --delay 80 1 && echo "double-clicked ${args.x},${args.y}"`;
        break;
      }

      case 'desktop_right_click': {
        command = `${DISPLAY_PREFIX} xdotool mousemove ${args.x} ${args.y} click 3 && echo "right-clicked ${args.x},${args.y}"`;
        break;
      }

      case 'desktop_type': {
        const delay = args.delay || 20;
        const encoded = Buffer.from(args.text, 'utf8').toString('base64');
        command = `echo ${JSON.stringify(encoded)} | base64 -d > /tmp/_dtype.txt && ${DISPLAY_PREFIX} xdotool type --clearmodifiers --delay ${delay} --file /tmp/_dtype.txt && echo "typed ${args.text.length} chars"`;
        break;
      }

      case 'desktop_key': {
        command = `${DISPLAY_PREFIX} xdotool key --clearmodifiers ${args.keys} && echo "key: ${args.keys}"`;
        break;
      }

      case 'desktop_scroll': {
        const amount = args.amount || 3;
        const btn = args.direction === 'up' ? 4 : 5;
        command = `${DISPLAY_PREFIX} xdotool mousemove ${args.x} ${args.y} click --repeat ${amount} ${btn} && echo "scrolled ${args.direction} x${amount} at ${args.x},${args.y}"`;
        break;
      }

      case 'desktop_drag': {
        command = `${DISPLAY_PREFIX} xdotool mousemove ${args.x1} ${args.y1} mousedown 1 mousemove --sync ${args.x2} ${args.y2} mouseup 1 && echo "dragged (${args.x1},${args.y1}) -> (${args.x2},${args.y2})"`;
        break;
      }

      case 'desktop_run': {
        const runLog = `/tmp/_run_${Date.now()}.log`;
        command = `su kali -c ${JSON.stringify(`DISPLAY=:0 XAUTHORITY=/home/kali/.Xauthority nohup bash -c ${JSON.stringify(args.app_command)} </dev/null >${runLog} 2>&1 &`)} && sleep 0.5 && echo "launched as kali — log: ${runLog}"`;
        break;
      }

      case 'desktop_get_window_list': {
        command = `${DISPLAY_PREFIX} xdotool search --name "" 2>/dev/null | head -50 | while read wid; do t=$(DISPLAY=:0 XAUTHORITY=/var/run/lightdm/root/:0 xdotool getwindowname $wid 2>/dev/null); [ -n "$t" ] && echo "$wid  $t"; done`;
        break;
      }

      case 'desktop_focus_window': {
        command = `${DISPLAY_PREFIX} bash -c 'xdotool windowfocus --sync ${args.window_id} && xdotool windowraise ${args.window_id} && echo "focused ${args.window_id}"'`;
        break;
      }

      case 'desktop_get_cursor_pos': {
        command = `${DISPLAY_PREFIX} xdotool getmouselocation`;
        break;
      }

      case 'desktop_get_screen_size': {
        command = `${DISPLAY_PREFIX} xdotool getdisplaygeometry`;
        break;
      }

      // ── Browser perception tools ──────────────────────────────────────────
      case 'browser_navigate': {
        const state = await perceptionCall('POST', '/navigate', {
          url: args.url,
          proxy_port: args.proxy_port || null,
        });
        const screenshot = state.screenshot || null;
        delete state.screenshot;
        res.json({ success: true, isBrowser: true, result: JSON.stringify(state, null, 2), screenshot });
        return;
      }

      case 'browser_click': {
        if (!args.selector && args.x === undefined) {
          return res.status(400).json({ error: 'browser_click requires selector or x,y coordinates' });
        }
        const state = await perceptionCall('POST', '/click', {
          selector: args.selector || null,
          x: args.x !== undefined ? args.x : null,
          y: args.y !== undefined ? args.y : null,
        });
        const screenshot = state.screenshot || null;
        delete state.screenshot;
        res.json({ success: true, isBrowser: true, result: JSON.stringify(state, null, 2), screenshot });
        return;
      }

      case 'browser_type': {
        const state = await perceptionCall('POST', '/type', {
          selector: args.selector || null,
          text: args.text,
        });
        const screenshot = state.screenshot || null;
        delete state.screenshot;
        res.json({ success: true, isBrowser: true, result: JSON.stringify(state, null, 2), screenshot });
        return;
      }

      case 'browser_get_state': {
        const state = await perceptionCall('GET', '/state', null);
        const screenshot = state.screenshot || null;
        delete state.screenshot;
        res.json({ success: true, isBrowser: true, result: JSON.stringify(state, null, 2), screenshot });
        return;
      }

      case 'browser_screenshot': {
        const data = await perceptionCall('GET', '/screenshot', null);
        res.json({ success: true, isImage: true, data: data.screenshot, mimeType: 'image/png' });
        return;
      }

      case 'browser_eval': {
        const data = await perceptionCall('POST', '/eval', { js: args.js });
        res.json({ success: true, result: JSON.stringify(data.result, null, 2) });
        return;
      }

      case 'browser_get_network': {
        const data = await perceptionCall('GET', '/network', null);
        res.json({ success: true, result: JSON.stringify(data.requests, null, 2) });
        return;
      }

      case 'browser_set_proxy': {
        const data = await perceptionCall('POST', '/proxy', {
          enabled: args.enabled,
          host: args.host || '127.0.0.1',
          port: args.port || 8080,
        });
        res.json({ success: true, result: JSON.stringify(data, null, 2) });
        return;
      }

      case 'browser_close': {
        const data = await perceptionCall('POST', '/close', {});
        // Reset ready flag so next call restarts the server
        perceptionReady = false;
        res.json({ success: true, result: JSON.stringify(data, null, 2) });
        return;
      }

      default:
        return res.status(400).json({ error: `Unknown tool: ${tool_name}` });
    }

    const result = await executeKaliCommand(command);

    if (isScreenshot) {
      const base64 = result.stdout.toString('utf8').trim();
      if (!base64.startsWith('iVBORw0KGgo')) {
        return res.json({ success: false, error: `Screenshot failed: ${result.stderr || 'invalid PNG'}` });
      }
      res.json({ success: true, isImage: true, data: base64, mimeType: 'image/png' });
    } else {
      const text = (result.stdout.toString('utf8') + result.stderr).trim() || `exit: ${result.code}`;
      res.json({ success: true, result: text });
    }

  } catch (error) {
    res.status(500).json({ success: false, error: error.message });
  }
});

const server = app.listen(PORT, '0.0.0.0', () => {
  log('info', 'desktop_bridge_started', { port: PORT, pool: SSH_POOL_SIZE, host: process.env.KALI_HOST });
});

process.on('SIGTERM', () => {
  log('info', 'sigterm_received');
  server.close(() => process.exit(0));
});
