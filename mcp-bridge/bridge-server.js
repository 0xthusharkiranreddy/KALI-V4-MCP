const express = require('express');
const cors = require('cors');
const { spawn } = require('child_process');
const crypto = require('crypto');
const EventEmitter = require('events');

const app = express();
app.use(cors());
app.use(express.json());

const PORT = process.env.PORT || 3001;
const COMMAND_TIMEOUT = parseInt(process.env.COMMAND_TIMEOUT) || 3600000;
const SSH_POOL_SIZE = parseInt(process.env.SSH_POOL_SIZE) || 5;
const KALI_PORT = parseInt(process.env.KALI_PORT) || 22;

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

// ─── Job store ────────────────────────────────────────────────────────────────
const jobs = new Map();
const jobEvents = new EventEmitter();
jobEvents.setMaxListeners(2000); // one listener per concurrent sync call

function generateJobId() {
  return crypto.randomBytes(8).toString('hex');
}

function startJob(command) {
  const jobId = generateJobId();
  const pidFile = `/tmp/job_${jobId}.pid`;
  const socketPath = getSocketPath();

  // Base64-encode the command so that the remote bash receives it verbatim —
  // prevents the outer shell from expanding $vars / $(subshells) inside
  // double-quoted strings before bash -c sees them (the for-loop / variable
  // scoping bug).  Single quotes around the whole remote snippet protect $$
  // from local-shell expansion; ${pidFile} and ${b64cmd} are JS substitutions.
  const b64cmd = Buffer.from(command).toString('base64');
  const sshCmd =
    `ssh -i /root/.ssh/id_ed25519 -p ${KALI_PORT} ` +
    `-o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null ` +
    `-o ControlMaster=auto -o ControlPath=${socketPath} -o ControlPersist=1h ` +
    `${process.env.KALI_USERNAME}@${process.env.KALI_HOST} ` +
    `'echo $$ > ${pidFile} && exec bash -c "$(echo ${b64cmd} | base64 -d)"'`;

  // Direct SSH — no docker exec relay, no docker.sock required
  const proc = spawn('sh', ['-c', sshCmd]);

  const job = {
    jobId, command, pidFile,
    status: 'running',
    startTime: Date.now(),
    endTime: null,
    output: '',
    exitCode: null,
    error: null,
    proc,
  };

  const evict = () => setTimeout(() => jobs.delete(jobId), 30 * 60 * 1000);

  const timer = setTimeout(() => {
    proc.kill();
    job.status = 'timeout';
    job.output += `\n[timed out after ${COMMAND_TIMEOUT / 1000}s]`;
    job.endTime = Date.now();
    jobEvents.emit(jobId);
    evict();
  }, COMMAND_TIMEOUT);

  const MAX_OUTPUT = 10 * 1024 * 1024;
  const appendOutput = (chunk) => {
    job.output += chunk;
    if (job.output.length > MAX_OUTPUT) {
      job.output = '[...output truncated, showing last 10MB...]\n' +
                   job.output.slice(job.output.length - MAX_OUTPUT);
    }
  };
  proc.stdout.on('data', (data) => { appendOutput(data.toString()); });
  proc.stderr.on('data', (data) => { appendOutput(data.toString()); });

  proc.on('close', (code) => {
    clearTimeout(timer);
    if (job.status === 'running') {
      job.status = 'done';
      job.exitCode = code;
      job.endTime = Date.now();
    }
    if (!job.output.trim()) job.output = `Exit code: ${code}`;
    jobEvents.emit(jobId);
    evict();
  });

  proc.on('error', (err) => {
    clearTimeout(timer);
    job.status = 'error';
    job.error = err.message;
    job.endTime = Date.now();
    jobEvents.emit(jobId);
    evict(); // was missing before — error'd jobs are now evicted
  });

  jobs.set(jobId, job);
  log('info', 'job_started', { jobId, socket: socketPath, cmd: command.slice(0, 120) });
  return job;
}

// Direct SSH without PID-file wrapper — for internal fire-and-forget use only
function runSSHDirect(command) {
  const socketPath = getSocketPath();
  const b64cmd = Buffer.from(command).toString('base64');
  const sshCmd =
    `ssh -i /root/.ssh/id_ed25519 -p ${KALI_PORT} ` +
    `-o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null ` +
    `-o ControlMaster=auto -o ControlPath=${socketPath} ` +
    `${process.env.KALI_USERNAME}@${process.env.KALI_HOST} ` +
    `'bash -c "$(echo ${b64cmd} | base64 -d)"'`;
  return new Promise((resolve) => {
    const proc = spawn('sh', ['-c', sshCmd]);
    proc.on('close', resolve);
    proc.on('error', resolve);
  });
}

// EventEmitter-based wait — replaces 100ms busy-poll
function waitForJob(job) {
  return new Promise((resolve) => {
    if (job.status !== 'running') return resolve();
    jobEvents.once(job.jobId, resolve);
    // Re-check after registering — catches error/close that fired synchronously
    // before the .once was registered (Node.js EventEmitter synchronous-emit trap)
    if (job.status !== 'running') {
      jobEvents.removeListener(job.jobId, resolve);
      resolve();
    }
  });
}

// ─── Routes ───────────────────────────────────────────────────────────────────

app.get('/health', (req, res) => {
  res.json({ status: 'ok', service: 'mcp-bridge' });
});

app.get('/v1/jobs', (req, res) => {
  const list = [];
  for (const [, job] of jobs) {
    list.push({
      jobId: job.jobId,
      command: job.command.length > 100 ? job.command.slice(0, 100) + '...' : job.command,
      status: job.status,
      startTime: job.startTime,
      elapsed: (job.endTime || Date.now()) - job.startTime,
    });
  }
  res.json({ jobs: list });
});

app.get('/v1/jobs/:id', (req, res) => {
  const job = jobs.get(req.params.id);
  if (!job) return res.status(404).json({ error: 'Job not found' });
  res.json({
    jobId: job.jobId,
    command: job.command,
    status: job.status,
    startTime: job.startTime,
    elapsed: (job.endTime || Date.now()) - job.startTime,
    output: job.output,
    exitCode: job.exitCode,
    error: job.error,
  });
});

app.post('/v1/jobs/:id/kill', async (req, res) => {
  const job = jobs.get(req.params.id);
  if (!job) return res.status(404).json({ error: 'Job not found' });
  if (job.status !== 'running') return res.json({ message: `Job already ${job.status}` });
  job.proc.kill('SIGTERM'); // stops local ssh subprocess / output pipe
  job.status = 'killed';
  job.endTime = Date.now();
  // Kill the actual remote process on Kali using the stored PID file.
  // Use runSSHDirect (no PID wrapper) to avoid leaving a stray PID file.
  await runSSHDirect(
    `kill -TERM $(cat ${job.pidFile} 2>/dev/null) 2>/dev/null; rm -f ${job.pidFile}`
  );
  log('info', 'job_killed', { jobId: job.jobId });
  res.json({ message: `Job ${job.jobId} killed`, jobId: job.jobId });
});

// SSE streaming endpoint
app.post('/v1/tools/stream', (req, res) => {
  const { tool_name, arguments: args } = req.body;
  if (tool_name !== 'execute_kali_command' || !args || !args.command) {
    return res.status(400).json({ error: 'Invalid request' });
  }

  const job = startJob(args.command);

  res.setHeader('Content-Type', 'text/event-stream');
  res.setHeader('Cache-Control', 'no-cache');
  res.setHeader('Connection', 'keep-alive');
  res.flushHeaders();

  res.write(`data: ${JSON.stringify({ jobId: job.jobId, status: 'started' })}\n\n`);

  let lastLen = 0;
  const interval = setInterval(() => {
    const newChunk = job.output.slice(lastLen);
    if (newChunk) {
      const elapsed = (Date.now() - job.startTime) / 1000;
      res.write(`data: ${JSON.stringify({ jobId: job.jobId, chunk: newChunk, elapsed })}\n\n`);
      lastLen = job.output.length;
    }
    if (job.status !== 'running') {
      const elapsed = ((job.endTime || Date.now()) - job.startTime) / 1000;
      const remaining = job.output.slice(lastLen);
      if (remaining) res.write(`data: ${JSON.stringify({ jobId: job.jobId, chunk: remaining, elapsed })}\n\n`);
      res.write(`data: ${JSON.stringify({ jobId: job.jobId, done: true, exitCode: job.exitCode, elapsed })}\n\n`);
      clearInterval(interval);
      res.end();
    }
  }, 200);

  req.on('close', () => clearInterval(interval));
});

// Main execute endpoint — sync by default, async with async:true
app.post('/v1/tools/execute', async (req, res) => {
  const { tool_name, arguments: args, async: isAsync } = req.body;

  if (tool_name !== 'execute_kali_command' || !args || !args.command) {
    return res.status(400).json({ error: 'Invalid request' });
  }

  const job = startJob(args.command);

  if (isAsync) {
    return res.json({ success: true, jobId: job.jobId, status: 'running' });
  }

  await waitForJob(job);

  if (job.status === 'error') {
    return res.status(500).json({ success: false, error: job.error, jobId: job.jobId });
  }

  log('info', 'job_done', {
    jobId: job.jobId, status: job.status,
    exitCode: job.exitCode,
    elapsed: ((job.endTime || Date.now()) - job.startTime) / 1000,
  });
  res.json({ success: true, result: job.output, jobId: job.jobId });
});

// ─── Startup & graceful shutdown ──────────────────────────────────────────────
const server = app.listen(PORT, '0.0.0.0', () => {
  log('info', 'bridge_started', { port: PORT, pool: SSH_POOL_SIZE, host: process.env.KALI_HOST });
});

process.on('SIGTERM', () => {
  log('info', 'sigterm_received');
  server.close(() => process.exit(0));
});
