<?php
/**
 * xsukax One Time E2EE File Transfer
 * End-to-end encrypted, one-time file transfer with AES-256-GCM.
 * Files are encrypted client-side before upload using the transfer code.
 *
 * @license GPL-3.0
 * @author  xsukax
 * @version 3.0.0
 */

// ── Security headers ─────────────────────────────────────────────────────────
header('X-Content-Type-Options: nosniff');
header('X-Frame-Options: DENY');
header('Referrer-Policy: no-referrer');
header('X-XSS-Protection: 1; mode=block');
header("Content-Security-Policy: default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; connect-src 'self'");
header('Permissions-Policy: camera=(), microphone=(), geolocation=()');

// ── Configuration ─────────────────────────────────────────────────────────────
define('UPLOAD_DIR',    __DIR__ . '/transfers/');
define('RATE_DIR',      __DIR__ . '/transfers/.rate/');
define('MAX_FILE_SIZE', 200 * 1024 * 1024);    // 200 MB
define('FILE_LIFETIME', 1800);                  // 30 minutes
define('CODE_LENGTH',   6);
define('RATE_WINDOW',   60);                    // seconds
define('RATE_LIMIT',    10);                    // requests per window per IP
define('MAX_FILENAME',  255);
define('AES_GCM_IV_BYTES', 12);                 // AES-GCM requires 12-byte IV
// Base64 overhead ≈ 4/3; add 20% headroom for form fields
define('MAX_B64_LEN',   (int)(MAX_FILE_SIZE * 1.4));

// ── Bootstrap directories ─────────────────────────────────────────────────────
foreach ([UPLOAD_DIR, RATE_DIR] as $dir) {
    if (!is_dir($dir)) {
        mkdir($dir, 0700, true);
    }
}

// Drop an .htaccess in the uploads dir to block direct HTTP access
$htaccess = UPLOAD_DIR . '.htaccess';
if (!file_exists($htaccess)) {
    file_put_contents($htaccess, "Options -Indexes\nDeny from all\n");
}

// ── Bootstrap ─────────────────────────────────────────────────────────────────
cleanupExpiredFiles();

$action = filter_input(INPUT_GET,  'action', FILTER_SANITIZE_SPECIAL_CHARS)
       ?? filter_input(INPUT_POST, 'action', FILTER_SANITIZE_SPECIAL_CHARS)
       ?? 'interface';

switch ($action) {
    case 'generate_code': generateCode();    break;
    case 'upload':        handleUpload();    break;
    case 'check':         checkFile();       break;
    case 'download':      handleDownload();  break;
    default:              renderInterface(); break;
}

// ── Rate limiter (flat-file token bucket) ─────────────────────────────────────
function checkRateLimit(): bool {
    $ip      = hash('sha256', $_SERVER['REMOTE_ADDR'] ?? 'unknown');
    $path    = RATE_DIR . $ip . '.json';
    $now     = time();
    $data    = ['count' => 0, 'window_start' => $now];

    if (file_exists($path)) {
        $raw = file_get_contents($path);
        $tmp = json_decode($raw, true);
        if (is_array($tmp)) $data = $tmp;
    }

    if (($now - $data['window_start']) > RATE_WINDOW) {
        $data = ['count' => 0, 'window_start' => $now];
    }

    $data['count']++;
    file_put_contents($path, json_encode($data), LOCK_EX);

    return $data['count'] <= RATE_LIMIT;
}

// ── Helpers ───────────────────────────────────────────────────────────────────
function jsonError(int $code, string $msg): never {
    http_response_code($code);
    echo json_encode(['error' => $msg]);
    exit;
}

function validateCode(string $code): bool {
    return (bool) preg_match('/^[A-Z0-9]{' . CODE_LENGTH . '}$/', $code);
}

function safeFilename(string $name): string {
    // Strip any path components, then allow only safe characters
    $name = basename($name);
    $name = preg_replace('/[^\w.\-() ]/', '_', $name);
    $name = trim($name, '. ');
    $name = substr($name, 0, MAX_FILENAME);
    return $name ?: 'file';
}

function filePaths(string $code): array {
    $hash = hash('sha256', $code);
    return [
        'enc'  => UPLOAD_DIR . $hash . '.enc',
        'meta' => UPLOAD_DIR . $hash . '.meta',
    ];
}

// ── Actions ───────────────────────────────────────────────────────────────────
function generateCode(): void {
    header('Content-Type: application/json');
    if (!checkRateLimit()) jsonError(429, 'Too many requests');

    $chars = 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789'; // No I/O/0/1
    $code  = '';
    for ($i = 0; $i < CODE_LENGTH; $i++) {
        $code .= $chars[random_int(0, strlen($chars) - 1)];
    }
    echo json_encode(['code' => $code]);
    exit;
}

function handleUpload(): void {
    header('Content-Type: application/json');
    if (!checkRateLimit()) jsonError(429, 'Too many requests');

    // ── Validate code ─────────────────────────────────────────────────────
    $code = $_POST['code'] ?? '';
    if (!validateCode(strtoupper($code))) jsonError(400, 'Invalid code format');
    $code = strtoupper($code);

    // ── Reject if a file already exists for this code ─────────────────────
    $paths = filePaths($code);
    if (file_exists($paths['enc'])) jsonError(409, 'Code already in use');

    // ── Validate base64 lengths before decoding ───────────────────────────
    $b64data = $_POST['encrypted_data'] ?? '';
    $b64iv   = $_POST['iv']             ?? '';
    $rawName = $_POST['filename']       ?? 'file';

    if (strlen($b64data) > MAX_B64_LEN) jsonError(413, 'Payload too large');
    if (empty($b64data) || empty($b64iv))  jsonError(400, 'Missing encrypted_data or IV');

    // Only valid base64 characters
    if (!preg_match('/^[A-Za-z0-9+\/=]+$/', $b64data)) jsonError(400, 'Invalid base64 data');
    if (!preg_match('/^[A-Za-z0-9+\/=]+$/', $b64iv))   jsonError(400, 'Invalid base64 IV');

    $encBytes = base64_decode($b64data, true);
    $ivBytes  = base64_decode($b64iv,   true);

    if ($encBytes === false || $ivBytes === false) jsonError(400, 'Base64 decode failed');

    // ── Validate IV length (AES-GCM = 12 bytes) ───────────────────────────
    if (strlen($ivBytes) !== AES_GCM_IV_BYTES) jsonError(400, 'Invalid IV length');

    // ── Validate payload size (after decoding) ────────────────────────────
    if (strlen($encBytes) > MAX_FILE_SIZE) jsonError(413, 'Encrypted payload exceeds 200 MB');

    // ── Sanitize filename ─────────────────────────────────────────────────
    $filename = safeFilename($rawName);

    // ── Persist ───────────────────────────────────────────────────────────
    if (file_put_contents($paths['enc'], $encBytes, LOCK_EX) === false) {
        jsonError(500, 'Storage error');
    }

    $meta = json_encode([
        'filename' => $filename,
        'iv'       => base64_encode($ivBytes),
        'size'     => strlen($encBytes),
        'uploaded' => time(),
    ]);
    if (file_put_contents($paths['meta'], $meta, LOCK_EX) === false) {
        @unlink($paths['enc']);
        jsonError(500, 'Metadata storage error');
    }

    echo json_encode(['status' => 'uploaded', 'code' => $code]);
    exit;
}

function checkFile(): void {
    header('Content-Type: application/json');
    if (!checkRateLimit()) jsonError(429, 'Too many requests');

    $code = strtoupper(filter_input(INPUT_GET, 'code', FILTER_SANITIZE_SPECIAL_CHARS) ?? '');
    if (!validateCode($code)) jsonError(400, 'Invalid code');

    $paths = filePaths($code);
    if (!file_exists($paths['enc']) || !file_exists($paths['meta'])) {
        jsonError(404, 'File not found or expired');
    }

    $meta = json_decode(file_get_contents($paths['meta']), true);
    if (!is_array($meta)) jsonError(500, 'Corrupt metadata');

    echo json_encode([
        'exists'   => true,
        'filename' => $meta['filename'],
        'size'     => $meta['size'],
    ]);
    exit;
}

function handleDownload(): void {
    header('Content-Type: application/json');
    if (!checkRateLimit()) jsonError(429, 'Too many requests');

    $code = strtoupper(filter_input(INPUT_GET, 'code', FILTER_SANITIZE_SPECIAL_CHARS) ?? '');
    if (!validateCode($code)) jsonError(400, 'Invalid code');

    $paths = filePaths($code);

    // ── Atomic one-time download via exclusive lock ────────────────────────
    $lockFile = UPLOAD_DIR . hash('sha256', $code) . '.lock';
    $lock     = fopen($lockFile, 'c');
    if (!$lock || !flock($lock, LOCK_EX | LOCK_NB)) {
        jsonError(409, 'File is being downloaded by another request');
    }

    if (!file_exists($paths['enc']) || !file_exists($paths['meta'])) {
        flock($lock, LOCK_UN);
        fclose($lock);
        @unlink($lockFile);
        jsonError(404, 'File not found or expired');
    }

    $meta     = json_decode(file_get_contents($paths['meta']), true);
    $encBytes = file_get_contents($paths['enc']);

    if (!is_array($meta) || $encBytes === false) {
        flock($lock, LOCK_UN);
        fclose($lock);
        @unlink($lockFile);
        jsonError(500, 'Could not read file');
    }

    // Delete before responding (one-time use)
    @unlink($paths['enc']);
    @unlink($paths['meta']);
    flock($lock, LOCK_UN);
    fclose($lock);
    @unlink($lockFile);

    echo json_encode([
        'encrypted_data' => base64_encode($encBytes),
        'iv'             => $meta['iv'],
        'filename'       => $meta['filename'],
    ]);
    exit;
}

function cleanupExpiredFiles(): void {
    if (!is_dir(UPLOAD_DIR)) return;
    $now   = time();
    $metas = glob(UPLOAD_DIR . '*.meta');
    if (!$metas) return;

    foreach ($metas as $metaFile) {
        $raw  = @file_get_contents($metaFile);
        $meta = $raw ? json_decode($raw, true) : null;
        if (!is_array($meta)) { @unlink($metaFile); continue; }

        if (($now - (int)$meta['uploaded']) > FILE_LIFETIME) {
            $enc = str_replace('.meta', '.enc', $metaFile);
            @unlink($enc);
            @unlink($metaFile);
            @unlink(str_replace('.meta', '.lock', $metaFile));
        }
    }

    // Also purge stale rate-limit windows
    if (is_dir(RATE_DIR)) {
        foreach (glob(RATE_DIR . '*.json') ?: [] as $rf) {
            $rd = json_decode(@file_get_contents($rf), true);
            if (!$rd || ($now - (int)$rd['window_start']) > RATE_WINDOW * 10) @unlink($rf);
        }
    }
}

// ── Interface ─────────────────────────────────────────────────────────────────
function renderInterface(): void { ?>
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>xsukax One Time E2EE File Transfer</title>
<style>
* { margin: 0; padding: 0; box-sizing: border-box; }
body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Arial, sans-serif; background: #f6f8fa; color: #24292f; line-height: 1.6; }
.container { max-width: 780px; margin: 48px auto; padding: 0 20px; }
.header { text-align: center; margin-bottom: 32px; }
.header h1 { font-size: 28px; font-weight: 700; color: #24292f; margin-bottom: 6px; }
.header p { color: #57606a; font-size: 14px; }
.badge { display: inline-flex; align-items: center; gap: 5px; background: #dafbe1; color: #1a7f37; padding: 3px 12px; border-radius: 20px; font-size: 12px; font-weight: 600; margin-top: 8px; border: 1px solid #2da44e44; }
.card { background: #ffffff; border: 1px solid #d0d7de; border-radius: 8px; padding: 28px; margin-bottom: 20px; box-shadow: 0 1px 3px rgba(27,31,36,.06); }
.tabs { display: flex; gap: 0; margin-bottom: 24px; border-bottom: 1px solid #d0d7de; }
.tab { padding: 8px 18px; background: none; border: none; border-bottom: 3px solid transparent; color: #57606a; cursor: pointer; font-size: 14px; font-weight: 500; transition: color .15s, border-color .15s; margin-bottom: -1px; }
.tab:hover { color: #0969da; }
.tab.active { color: #0969da; border-bottom-color: #fd8c73; font-weight: 600; }
.tab-content { display: none; }
.tab-content.active { display: block; }
.input-group { margin-bottom: 16px; }
.input-group label { display: block; font-size: 14px; font-weight: 600; color: #24292f; margin-bottom: 6px; }
.input-group input[type="text"], .input-group input[type="file"] { width: 100%; padding: 7px 12px; background: #f6f8fa; border: 1px solid #d0d7de; border-radius: 6px; color: #24292f; font-size: 14px; transition: border-color .15s, box-shadow .15s; }
.input-group input[type="text"]:focus { outline: none; border-color: #0969da; box-shadow: 0 0 0 3px rgba(9,105,218,.1); background: #fff; }
.input-group input[type="text"]::placeholder { color: #8c959f; }
.btn { display: inline-flex; align-items: center; gap: 6px; padding: 7px 16px; background: #2da44e; color: #fff; border: 1px solid rgba(31,35,40,.15); border-radius: 6px; font-size: 14px; font-weight: 600; cursor: pointer; transition: background .15s; }
.btn:hover { background: #2c974b; }
.btn:disabled { background: #8c959f; cursor: not-allowed; opacity: .7; }
.btn-secondary { background: #f6f8fa; color: #24292f; border-color: #d0d7de; }
.btn-secondary:hover { background: #eaeef2; }
.code-box { background: #f6f8fa; border: 2px dashed #d0d7de; border-radius: 8px; padding: 24px; text-align: center; margin: 18px 0; }
.code-box .lbl { font-size: 13px; color: #57606a; margin-bottom: 10px; font-weight: 500; }
.code-box .code { font-size: 40px; font-weight: 800; letter-spacing: 8px; color: #0969da; font-family: 'Courier New', monospace; user-select: all; }
.code-box .actions { margin-top: 14px; display: flex; gap: 8px; justify-content: center; }
.progress-wrap { background: #eaeef2; border-radius: 6px; height: 8px; overflow: hidden; margin: 14px 0; }
.progress-bar { height: 100%; background: linear-gradient(90deg, #2da44e, #26a641); border-radius: 6px; transition: width .3s; }
.alert { padding: 12px 14px; border-radius: 6px; font-size: 13px; margin: 14px 0; }
.alert-info    { background: #ddf4ff; color: #0550ae; border: 1px solid #54aeff44; }
.alert-success { background: #dafbe1; color: #1a7f37; border: 1px solid #2da44e44; }
.alert-error   { background: #ffebe9; color: #cf222e; border: 1px solid #ff818266; }
.alert-warn    { background: #fff8c5; color: #9a6700; border: 1px solid #d4a72c44; }
.alert strong  { font-weight: 600; }
.meta-row { font-size: 12px; margin-top: 4px; color: inherit; opacity: .85; }
.divider { border: none; border-top: 1px solid #d0d7de; margin: 20px 0; }
.footer { text-align: center; color: #57606a; font-size: 12px; padding: 20px 0 10px; border-top: 1px solid #d0d7de; }
.footer a { color: #0969da; text-decoration: none; }
.footer a:hover { text-decoration: underline; }
.dot-sep { margin: 0 6px; color: #d0d7de; }
</style>
</head>
<body>
<div class="container">

  <div class="header">
    <h1>&#128274; xsukax One Time E2EE File Transfer</h1>
    <p>End-to-end encrypted &amp; self-destructing file sharing powered by AES-256-GCM</p>
    <div class="badge">&#128737; Zero-knowledge &nbsp;&bull;&nbsp; One-time download &nbsp;&bull;&nbsp; 30-minute expiry</div>
  </div>

  <div class="card">
    <div class="tabs">
      <button class="tab active" id="tab-send"    onclick="switchTab('send',event)">&#8679; Send File</button>
      <button class="tab"        id="tab-receive" onclick="switchTab('receive',event)">&#8681; Receive File</button>
    </div>

    <!-- ── SEND ── -->
    <div id="send-tab" class="tab-content active">
      <div class="alert alert-info">
        <strong>How it works:</strong> Your file is encrypted <em>in your browser</em> with AES-256-GCM before it leaves your device.
        The server stores only ciphertext. The transfer code is the sole key — share it only with your recipient.
      </div>
      <div class="input-group">
        <label>Select file <span style="color:#57606a;font-weight:400;">(max 200 MB)</span></label>
        <input type="file" id="fileInput" accept="*/*">
      </div>
      <button class="btn" id="sendBtn" onclick="startSend()">&#128274; Encrypt &amp; Upload</button>
      <div id="send-status"></div>
    </div>

    <!-- ── RECEIVE ── -->
    <div id="receive-tab" class="tab-content">
      <div class="alert alert-info">
        <strong>One-time download:</strong> Enter the 6-character code to download and decrypt the file.
        The file is deleted from the server immediately after download, or it expires automatically after 30 minutes.
      </div>
      <div class="input-group">
        <label>Transfer code</label>
        <input type="text" id="codeInput" placeholder="XXXXXX" maxlength="6"
               autocomplete="off" autocorrect="off" autocapitalize="characters" spellcheck="false">
      </div>
      <button class="btn" id="receiveBtn" onclick="startReceive()">&#128275; Download &amp; Decrypt</button>
      <div id="receive-status"></div>
    </div>
  </div>

  <div class="footer">
    <p>
      Licensed under <a href="https://www.gnu.org/licenses/gpl-3.0.html" target="_blank" rel="noopener">GPL-3.0</a>
      <span class="dot-sep">|</span>
      Created by xsukax
    </p>
    <p style="margin-top:4px;color:#8c959f;">
      Client-side encryption
      <span class="dot-sep">&#9679;</span>
      Zero-knowledge architecture
      <span class="dot-sep">&#9679;</span>
      Auto-expiring transfers
    </p>
  </div>
</div>

<script>
'use strict';

// ── Crypto helpers ────────────────────────────────────────────────────────────
async function deriveKey(code) {
    const enc  = new TextEncoder();
    const raw  = await crypto.subtle.importKey('raw', enc.encode(code), 'PBKDF2', false, ['deriveKey']);
    return crypto.subtle.deriveKey(
        { name: 'PBKDF2', salt: enc.encode('xsukax-e2ee-transfer-v3'), iterations: 200000, hash: 'SHA-256' },
        raw,
        { name: 'AES-GCM', length: 256 },
        false,
        ['encrypt', 'decrypt']
    );
}

async function encryptFile(file, code) {
    const key  = await deriveKey(code);
    const iv   = crypto.getRandomValues(new Uint8Array(12));
    const data = await file.arrayBuffer();
    const enc  = await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, key, data);
    return { encrypted: new Uint8Array(enc), iv };
}

async function decryptFile(encBuf, ivArr, code) {
    const key = await deriveKey(code);
    try {
        const dec = await crypto.subtle.decrypt({ name: 'AES-GCM', iv: ivArr }, key, encBuf);
        return new Uint8Array(dec);
    } catch {
        throw new Error('Decryption failed — wrong code or corrupted file');
    }
}

// ── Base64 utils ──────────────────────────────────────────────────────────────
function toB64(buf) {
    let s = '';
    const b = new Uint8Array(buf);
    for (let i = 0; i < b.length; i++) s += String.fromCharCode(b[i]);
    return btoa(s);
}
function fromB64(s) {
    const b = atob(s), r = new Uint8Array(b.length);
    for (let i = 0; i < b.length; i++) r[i] = b.charCodeAt(i);
    return r.buffer;
}

// ── Tab switching ─────────────────────────────────────────────────────────────
function switchTab(tab, e) {
    document.querySelectorAll('.tab').forEach(t => t.classList.remove('active'));
    document.querySelectorAll('.tab-content').forEach(c => c.classList.remove('active'));
    e.currentTarget.classList.add('active');
    document.getElementById(tab + '-tab').classList.add('active');
}

// ── Format bytes ──────────────────────────────────────────────────────────────
function fmtSize(n) {
    if (n < 1024) return n + ' B';
    if (n < 1048576) return (n/1024).toFixed(1) + ' KB';
    return (n/1048576).toFixed(2) + ' MB';
}

// ── Send ──────────────────────────────────────────────────────────────────────
async function startSend() {
    const fileInput = document.getElementById('fileInput');
    const file = fileInput.files[0];
    if (!file) { setStatus('send', 'Please select a file.', 'error'); return; }
    if (file.size > <?= MAX_FILE_SIZE ?>) {
        setStatus('send', 'File exceeds the 200 MB limit.', 'error');
        return;
    }

    const btn = document.getElementById('sendBtn');
    btn.disabled = true;

    try {
        setStatus('send', 'Generating secure code&hellip;', 'info');
        const cRes  = await safeFetch('?action=generate_code');
        const cData = await cRes.json();
        if (!cRes.ok) throw new Error(cData.error || 'Code generation failed');
        const code = cData.code;

        setStatus('send', 'Encrypting with AES-256-GCM (PBKDF2 × 200 000 rounds)&hellip;', 'info');
        const { encrypted, iv } = await encryptFile(file, code);

        setStatus('send', 'Uploading ciphertext&hellip;', 'info');
        const fd = new FormData();
        fd.append('action',         'upload');
        fd.append('code',           code);
        fd.append('encrypted_data', toB64(encrypted));
        fd.append('iv',             toB64(iv));
        fd.append('filename',       file.name);

        const uRes  = await safeFetch('', { method: 'POST', body: fd });
        const uData = await uRes.json();
        if (!uRes.ok) throw new Error(uData.error || 'Upload failed');

        document.getElementById('send-status').innerHTML = `
          <div class="code-box">
            <div class="lbl">&#128228; Share this code with the recipient</div>
            <div class="code" id="tcode">${code}</div>
            <div class="actions">
              <button class="btn btn-secondary" onclick="copyCode('${code}',this)">&#128203; Copy Code</button>
            </div>
          </div>
          <div class="alert alert-success">
            <strong>&#10003; Uploaded successfully!</strong>
            <div class="meta-row">File: ${escHtml(file.name)} &nbsp;|&nbsp; ${fmtSize(file.size)}</div>
            <div class="meta-row">Expires in 30 minutes or on first download.</div>
          </div>`;

    } catch (err) {
        setStatus('send', 'Error: ' + escHtml(err.message), 'error');
    } finally {
        btn.disabled = false;
    }
}

// ── Receive ───────────────────────────────────────────────────────────────────
async function startReceive() {
    const code = document.getElementById('codeInput').value.toUpperCase().trim();
    if (!code || code.length !== <?= CODE_LENGTH ?>) {
        setStatus('receive', 'Please enter a valid <?= CODE_LENGTH ?>-character code.', 'error');
        return;
    }
    if (!/^[A-Z0-9]{<?= CODE_LENGTH ?>}$/.test(code)) {
        setStatus('receive', 'Code contains invalid characters.', 'error');
        return;
    }

    const btn = document.getElementById('receiveBtn');
    btn.disabled = true;

    try {
        setStatus('receive', 'Looking up file&hellip;', 'info');
        const ckRes  = await safeFetch('?action=check&code=' + encodeURIComponent(code));
        if (!ckRes.ok) { const j = await ckRes.json(); throw new Error(j.error || 'File not found'); }
        const info = await ckRes.json();

        setStatus('receive', `Downloading &ldquo;${escHtml(info.filename)}&rdquo; (${fmtSize(info.size)})&hellip;`, 'info');
        const dlRes  = await safeFetch('?action=download&code=' + encodeURIComponent(code));
        if (!dlRes.ok) { const j = await dlRes.json(); throw new Error(j.error || 'Download failed'); }
        const dl = await dlRes.json();

        setStatus('receive', 'Decrypting&hellip;', 'info');
        const enc = fromB64(dl.encrypted_data);
        const iv  = new Uint8Array(fromB64(dl.iv));
        const raw = await decryptFile(enc, iv, code);

        const url = URL.createObjectURL(new Blob([raw]));
        const a   = Object.assign(document.createElement('a'), { href: url, download: dl.filename });
        document.body.appendChild(a);
        a.click();
        document.body.removeChild(a);
        setTimeout(() => URL.revokeObjectURL(url), 10000);

        document.getElementById('receive-status').innerHTML = `
          <div class="alert alert-success">
            <strong>&#10003; Decrypted and saved!</strong>
            <div class="meta-row">File: ${escHtml(dl.filename)}</div>
            <div class="meta-row">The file has been permanently deleted from the server.</div>
          </div>`;
        document.getElementById('codeInput').value = '';

    } catch (err) {
        setStatus('receive', 'Error: ' + escHtml(err.message), 'error');
    } finally {
        btn.disabled = false;
    }
}

// ── Utils ─────────────────────────────────────────────────────────────────────
async function safeFetch(url, opts) {
    const r = await fetch(url, opts);
    return r;
}

function setStatus(tab, msg, type) {
    const map  = { info: 'alert-info', success: 'alert-success', error: 'alert-error', warn: 'alert-warn' };
    const cls  = map[type] || '';
    document.getElementById(tab + '-status').innerHTML =
        `<div class="alert ${cls}">${msg}</div>`;
}

function copyCode(code, btn) {
    navigator.clipboard.writeText(code).then(() => {
        const orig = btn.innerHTML;
        btn.innerHTML = '&#10003; Copied!';
        setTimeout(() => { btn.innerHTML = orig; }, 2200);
    }).catch(() => setStatus('send', 'Could not access clipboard.', 'warn'));
}

function escHtml(s) {
    return String(s).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;');
}

// Auto-uppercase + filter code input
document.getElementById('codeInput').addEventListener('input', function() {
    this.value = this.value.toUpperCase().replace(/[^A-Z0-9]/g, '');
});
</script>
</body>
</html>
<?php } ?>