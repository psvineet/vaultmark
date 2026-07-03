<?php
/**
 * Vaultmark — a single-file PHP bookmark manager.
 * Storage: JSON files in /data (protected via .htaccess).
 * Theme: cream background, navy blue + gold accents.
 */

session_start();
error_reporting(E_ALL & ~E_DEPRECATED & ~E_NOTICE);

/* ---------------------------------------------------------
   CONFIG & PATHS
--------------------------------------------------------- */
define('DATA_DIR', __DIR__ . '/data');
define('USERS_FILE', DATA_DIR . '/users.json');
define('BOOKMARKS_FILE', DATA_DIR . '/bookmarks.json');
define('ATTEMPTS_FILE', DATA_DIR . '/attempts.json');
define('HTACCESS_FILE', DATA_DIR . '/.htaccess');
define('APP_NAME', 'Vaultmark');

/* Brute-force protection tuning */
define('MAX_ATTEMPTS', 5);          // failed attempts allowed
define('ATTEMPT_WINDOW', 15 * 60);  // seconds — window in which attempts are counted
define('LOCKOUT_TIME', 15 * 60);    // seconds — lockout duration once max attempts hit

/* ---------------------------------------------------------
   BOOTSTRAP: create data dir, seed files, lock down access
--------------------------------------------------------- */
function ensure_setup() {
    if (!is_dir(DATA_DIR)) {
        mkdir(DATA_DIR, 0755, true);
    }
    if (!file_exists(HTACCESS_FILE)) {
        $rules = "# Deny all direct access to this folder\n"
               . "<IfModule mod_authz_core.c>\n"
               . "    Require all denied\n"
               . "</IfModule>\n"
               . "<IfModule !mod_authz_core.c>\n"
               . "    Order allow,deny\n"
               . "    Deny from all\n"
               . "</IfModule>\n";
        file_put_contents(HTACCESS_FILE, $rules);
    }
    if (!file_exists(USERS_FILE)) {
        // Generate a random initial password instead of a guessable default.
        $genPass = bin2hex(random_bytes(5));
        $default = [ 'admin' => password_hash($genPass, PASSWORD_DEFAULT) ];
        save_json(USERS_FILE, $default);
        // Write the one-time generated password to a local file ONLY,
        // never rendered in the HTML/UI. Delete this file after first login.
        file_put_contents(DATA_DIR . '/INITIAL_PASSWORD.txt',
            "Username: admin\nPassword: {$genPass}\n\nDelete this file after you log in and change your password.\n");
    }
    if (!file_exists(BOOKMARKS_FILE)) {
        save_json(BOOKMARKS_FILE, []);
    }
    if (!file_exists(ATTEMPTS_FILE)) {
        save_json(ATTEMPTS_FILE, []);
    }
    $idx = DATA_DIR . '/index.html';
    if (!file_exists($idx)) file_put_contents($idx, '');
}
ensure_setup();

/* ---------------------------------------------------------
   JSON HELPERS (with file locking)
--------------------------------------------------------- */
function load_json($file) {
    if (!file_exists($file)) return [];
    $fp = fopen($file, 'r');
    if (!$fp) return [];
    flock($fp, LOCK_SH);
    $content = stream_get_contents($fp);
    flock($fp, LOCK_UN);
    fclose($fp);
    $data = json_decode($content, true);
    return is_array($data) ? $data : [];
}

function save_json($file, $data) {
    $fp = fopen($file, 'c');
    if (!$fp) return false;
    flock($fp, LOCK_EX);
    ftruncate($fp, 0);
    rewind($fp);
    fwrite($fp, json_encode($data, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES));
    fflush($fp);
    flock($fp, LOCK_UN);
    fclose($fp);
    return true;
}

/* ---------------------------------------------------------
   AUTH HELPERS
--------------------------------------------------------- */
function is_logged_in() {
    return !empty($_SESSION['user']);
}

function require_login_json() {
    if (!is_logged_in()) {
        header('Content-Type: application/json');
        http_response_code(401);
        echo json_encode(['ok' => false, 'error' => 'Not authenticated']);
        exit;
    }
}

function csrf_token() {
    if (empty($_SESSION['csrf'])) {
        $_SESSION['csrf'] = bin2hex(random_bytes(16));
    }
    return $_SESSION['csrf'];
}

function csrf_ok($token) {
    return !empty($_SESSION['csrf']) && hash_equals($_SESSION['csrf'], (string)$token);
}

function client_ip() {
    // REMOTE_ADDR only — proxy headers are attacker-controllable and not trusted here.
    return $_SERVER['REMOTE_ADDR'] ?? 'unknown';
}

/* ---------------------------------------------------------
   BRUTE-FORCE PROTECTION
--------------------------------------------------------- */
function bruteforce_status($key) {
    $attempts = load_json(ATTEMPTS_FILE);
    $now = time();
    $rec = $attempts[$key] ?? null;
    if (!$rec) return ['locked' => false, 'retry_after' => 0];

    if (!empty($rec['locked_until']) && $rec['locked_until'] > $now) {
        return ['locked' => true, 'retry_after' => $rec['locked_until'] - $now];
    }
    return ['locked' => false, 'retry_after' => 0];
}

function register_failed_attempt($key) {
    $attempts = load_json(ATTEMPTS_FILE);
    $now = time();
    $rec = $attempts[$key] ?? ['count' => 0, 'first_at' => $now, 'locked_until' => 0];

    // reset the counting window if it has expired
    if (($now - $rec['first_at']) > ATTEMPT_WINDOW) {
        $rec = ['count' => 0, 'first_at' => $now, 'locked_until' => 0];
    }
    $rec['count']++;
    if ($rec['count'] >= MAX_ATTEMPTS) {
        $rec['locked_until'] = $now + LOCKOUT_TIME;
    }
    $attempts[$key] = $rec;
    save_json(ATTEMPTS_FILE, $attempts);
}

function reset_attempts($key) {
    $attempts = load_json(ATTEMPTS_FILE);
    if (isset($attempts[$key])) {
        unset($attempts[$key]);
        save_json(ATTEMPTS_FILE, $attempts);
    }
}

/* ---------------------------------------------------------
   BOOKMARK HELPERS
--------------------------------------------------------- */
function gen_id() {
    return bin2hex(random_bytes(8));
}

function normalize_tags($raw) {
    $parts = array_map('trim', explode(',', (string)$raw));
    $parts = array_filter($parts, fn($t) => $t !== '');
    return array_values(array_unique($parts));
}

function extract_github($url, $github) {
    $github = trim((string)$github);
    if ($github !== '') return $github;
    if (preg_match('#^https?://github\.com/[^/\s]+(/[^/\s]+)?#i', $url, $m)) {
        return $m[0];
    }
    return '';
}

/* ---------------------------------------------------------
   ROUTER
--------------------------------------------------------- */
$action = $_GET['action'] ?? ($_POST['action'] ?? '');

/* ---- LOGIN ---- */
if ($action === 'login' && $_SERVER['REQUEST_METHOD'] === 'POST') {
    $username = trim($_POST['username'] ?? '');
    $password = (string)($_POST['password'] ?? '');
    $key = strtolower($username) . '|' . client_ip();

    $bf = bruteforce_status($key);
    if ($bf['locked']) {
        $mins = max(1, ceil($bf['retry_after'] / 60));
        $login_error = "Too many failed attempts. Try again in about {$mins} minute(s).";
    } else {
        usleep(300000); // slows down automated brute-force attempts
        $users = load_json(USERS_FILE);
        if (isset($users[$username]) && password_verify($password, $users[$username])) {
            reset_attempts($key);
            session_regenerate_id(true);
            $_SESSION['user'] = $username;
            header('Location: ' . strtok($_SERVER['REQUEST_URI'], '?'));
            exit;
        } else {
            register_failed_attempt($key);
            $login_error = 'Invalid username or password.';
        }
    }
}

/* ---- LOGOUT ---- */
if ($action === 'logout') {
    session_unset();
    session_destroy();
    header('Location: ' . strtok($_SERVER['REQUEST_URI'], '?'));
    exit;
}

/* ---- ADD BOOKMARK ---- */
if ($action === 'add' && $_SERVER['REQUEST_METHOD'] === 'POST') {
    require_login_json();
    header('Content-Type: application/json');
    if (!csrf_ok($_POST['csrf'] ?? '')) {
        echo json_encode(['ok' => false, 'error' => 'Bad CSRF token']);
        exit;
    }
    $name = trim($_POST['name'] ?? '');
    $url  = trim($_POST['url'] ?? '');
    $category = trim($_POST['category'] ?? 'Uncategorized');
    $github = extract_github($url, $_POST['github'] ?? '');
    $tags = normalize_tags($_POST['tags'] ?? '');

    if ($name === '' || $url === '' || !filter_var($url, FILTER_VALIDATE_URL)) {
        echo json_encode(['ok' => false, 'error' => 'Name and a valid URL are required.']);
        exit;
    }
    $bookmarks = load_json(BOOKMARKS_FILE);
    $entry = [
        'id' => gen_id(),
        'name' => $name,
        'url' => $url,
        'github' => $github,
        'category' => $category !== '' ? $category : 'Uncategorized',
        'tags' => $tags,
        'status' => 'unknown',
        'added' => date('c'),
    ];
    $bookmarks[] = $entry;
    save_json(BOOKMARKS_FILE, $bookmarks);
    echo json_encode(['ok' => true, 'bookmark' => $entry]);
    exit;
}

/* ---- EDIT BOOKMARK ---- */
if ($action === 'edit' && $_SERVER['REQUEST_METHOD'] === 'POST') {
    require_login_json();
    header('Content-Type: application/json');
    if (!csrf_ok($_POST['csrf'] ?? '')) {
        echo json_encode(['ok' => false, 'error' => 'Bad CSRF token']);
        exit;
    }
    $id = $_POST['id'] ?? '';
    $name = trim($_POST['name'] ?? '');
    $url  = trim($_POST['url'] ?? '');
    $category = trim($_POST['category'] ?? 'Uncategorized');
    $github = extract_github($url, $_POST['github'] ?? '');
    $tags = normalize_tags($_POST['tags'] ?? '');

    if ($id === '' || $name === '' || $url === '' || !filter_var($url, FILTER_VALIDATE_URL)) {
        echo json_encode(['ok' => false, 'error' => 'Name and a valid URL are required.']);
        exit;
    }
    $bookmarks = load_json(BOOKMARKS_FILE);
    $found = false;
    foreach ($bookmarks as &$b) {
        if ($b['id'] === $id) {
            $b['name'] = $name;
            $b['url'] = $url;
            $b['github'] = $github;
            $b['category'] = $category !== '' ? $category : 'Uncategorized';
            $b['tags'] = $tags;
            $b['status'] = 'unknown'; // url may have changed, re-check next crawl
            $found = true;
            break;
        }
    }
    unset($b);
    if (!$found) {
        echo json_encode(['ok' => false, 'error' => 'Bookmark not found.']);
        exit;
    }
    save_json(BOOKMARKS_FILE, $bookmarks);
    echo json_encode(['ok' => true, 'bookmark' => $b]);
    exit;
}

/* ---- DELETE BOOKMARK ---- */
if ($action === 'delete' && $_SERVER['REQUEST_METHOD'] === 'POST') {
    require_login_json();
    header('Content-Type: application/json');
    if (!csrf_ok($_POST['csrf'] ?? '')) {
        echo json_encode(['ok' => false, 'error' => 'Bad CSRF token']);
        exit;
    }
    $id = $_POST['id'] ?? '';
    $bookmarks = load_json(BOOKMARKS_FILE);
    $before = count($bookmarks);
    $bookmarks = array_values(array_filter($bookmarks, fn($b) => $b['id'] !== $id));
    save_json(BOOKMARKS_FILE, $bookmarks);
    echo json_encode(['ok' => true, 'deleted' => $before - count($bookmarks)]);
    exit;
}

/* ---- IMPORT BROWSER BOOKMARKS (Netscape HTML export format) ---- */
if ($action === 'import' && $_SERVER['REQUEST_METHOD'] === 'POST') {
    require_login_json();
    header('Content-Type: application/json');
    if (!csrf_ok($_POST['csrf'] ?? '')) {
        echo json_encode(['ok' => false, 'error' => 'Bad CSRF token']);
        exit;
    }
    if (empty($_FILES['file']) || $_FILES['file']['error'] !== UPLOAD_ERR_OK) {
        echo json_encode(['ok' => false, 'error' => 'No file uploaded or upload error.']);
        exit;
    }
    $html = file_get_contents($_FILES['file']['tmp_name']);
    if ($html === false || trim($html) === '') {
        echo json_encode(['ok' => false, 'error' => 'Could not read uploaded file.']);
        exit;
    }

    $imported = parse_netscape_bookmarks($html);

    $bookmarks = load_json(BOOKMARKS_FILE);
    $existingUrls = array_column($bookmarks, 'url');
    $addedCount = 0;
    foreach ($imported as $item) {
        if (in_array($item['url'], $existingUrls, true)) continue;
        $item['id'] = gen_id();
        $item['status'] = 'unknown';
        $item['added'] = date('c');
        $item['github'] = extract_github($item['url'], '');
        $bookmarks[] = $item;
        $existingUrls[] = $item['url'];
        $addedCount++;
    }
    save_json(BOOKMARKS_FILE, $bookmarks);
    echo json_encode(['ok' => true, 'imported' => $addedCount, 'total_found' => count($imported)]);
    exit;
}

function parse_netscape_bookmarks($html) {
    $results = [];
    libxml_use_internal_errors(true);
    $doc = new DOMDocument();
    $doc->loadHTML('<?xml encoding="utf-8" ?>' . $html);
    libxml_clear_errors();

    $body = $doc->getElementsByTagName('body')->item(0);
    if (!$body) return $results;

    $walk = function ($node, $category) use (&$walk, &$results) {
        foreach ($node->childNodes as $child) {
            if ($child->nodeName === 'h3') {
                $folderName = trim($child->textContent);
                $sibling = $child->nextSibling;
                while ($sibling && $sibling->nodeName !== 'dl') {
                    $sibling = $sibling->nextSibling;
                }
                if ($sibling) {
                    $walk($sibling, $folderName !== '' ? $folderName : $category);
                }
            } elseif ($child->nodeName === 'a') {
                $href = $child->getAttribute('href');
                $text = trim($child->textContent);
                $tagsAttr = $child->getAttribute('tags');
                if ($href) {
                    $results[] = [
                        'name' => $text !== '' ? $text : $href,
                        'url' => $href,
                        'category' => $category,
                        'tags' => $tagsAttr ? normalize_tags($tagsAttr) : [],
                    ];
                }
            } elseif ($child->hasChildNodes()) {
                $walk($child, $category);
            }
        }
    };

    $walk($body, 'Imported');
    return $results;
}

/* ---- CRAWL / LINK-CHECK ENDPOINT: ?action=crawl&cat=CategoryName ---- */
if ($action === 'crawl') {
    require_login_json();
    header('Content-Type: application/json');
    $cat = $_GET['cat'] ?? '';
    $bookmarks = load_json(BOOKMARKS_FILE);
    $checked = 0;
    foreach ($bookmarks as &$b) {
        if ($cat !== '' && $cat !== 'All' && $b['category'] !== $cat) continue;
        $b['status'] = check_url_status($b['url']);
        $checked++;
    }
    unset($b);
    save_json(BOOKMARKS_FILE, $bookmarks);
    echo json_encode(['ok' => true, 'checked' => $checked, 'category' => $cat ?: 'All', 'bookmarks' => $bookmarks]);
    exit;
}

function check_url_status($url) {
    if (!function_exists('curl_init')) return 'unknown';
    $ch = curl_init($url);
    curl_setopt_array($ch, [
        CURLOPT_NOBODY => true,
        CURLOPT_RETURNTRANSFER => true,
        CURLOPT_FOLLOWLOCATION => true,
        CURLOPT_MAXREDIRS => 5,
        CURLOPT_TIMEOUT => 6,
        CURLOPT_SSL_VERIFYPEER => false,
        CURLOPT_SSL_VERIFYHOST => false,
        CURLOPT_USERAGENT => 'Vaultmark-Crawler/1.0',
    ]);
    curl_exec($ch);
    $code = curl_getinfo($ch, CURLINFO_HTTP_CODE);
    $err = curl_errno($ch);
    curl_close($ch);
    if ($err) return 'broken';
    if ($code >= 200 && $code < 400) return 'ok';
    return 'broken';
}

/* ---- LIST (AJAX refresh, JSON) ---- */
if ($action === 'list') {
    require_login_json();
    header('Content-Type: application/json');
    echo json_encode(['ok' => true, 'bookmarks' => load_json(BOOKMARKS_FILE)]);
    exit;
}

/* ===========================================================
   From here on: normal HTML page rendering (login or dashboard)
=========================================================== */
$bookmarks = is_logged_in() ? load_json(BOOKMARKS_FILE) : [];
$categories = array_values(array_unique(array_map(fn($b) => $b['category'], $bookmarks)));
sort($categories);
$allTags = [];
foreach ($bookmarks as $b) { foreach ($b['tags'] as $t) { $allTags[$t] = true; } }
$allTags = array_keys($allTags);
sort($allTags);

/* Inline SVG logo mark — reused as header logo AND favicon */
$logoSvg = '<svg viewBox="0 0 64 64" xmlns="http://www.w3.org/2000/svg"><rect width="64" height="64" rx="16" fill="#0F2247"/><path d="M20 14h24a2 2 0 0 1 2 2v34l-14-9-14 9V16a2 2 0 0 1 2-2z" fill="#C9A227"/></svg>';
$favicon = 'data:image/svg+xml,' . rawurlencode($logoSvg);
?>
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title><?= APP_NAME ?> — Your Bookmarks, Safe Forever</title>
<link rel="icon" type="image/svg+xml" href="<?= $favicon ?>">
<link rel="preconnect" href="https://fonts.googleapis.com">
<link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
<link href="https://fonts.googleapis.com/css2?family=Noto+Sans:wght@400;500;600;700;800&display=swap" rel="stylesheet">
<style>
:root{
  --cream:#FBF6EC;
  --cream-alt:#F3ECDC;
  --navy:#0F2247;
  --navy-light:#1B3766;
  --gold:#C9A227;
  --gold-light:#E4C55E;
  --text:#20293D;
  --danger:#B4432D;
  --ok:#2E7D46;
  --radius:12px;
  --shadow:0 4px 14px rgba(15,34,71,0.10);
  --ease:cubic-bezier(.22,1,.36,1);
}
*{box-sizing:border-box;}
html{scroll-behavior:smooth;}
body{
  margin:0;
  font-family:'Noto Sans',system-ui,-apple-system,Arial,sans-serif;
  background:var(--cream);
  color:var(--text);
  animation:pageFade .5s var(--ease);
}
a{color:var(--navy);text-decoration:none;}
h1,h2,h3{color:var(--navy);margin:0 0 8px;}

@keyframes pageFade{ from{opacity:0;} to{opacity:1;} }
@keyframes fadeInUp{ from{opacity:0; transform:translateY(14px);} to{opacity:1; transform:translateY(0);} }
@keyframes fadeIn{ from{opacity:0;} to{opacity:1;} }
@keyframes popIn{ from{opacity:0; transform:scale(.92) translateY(10px);} to{opacity:1; transform:scale(1) translateY(0);} }
@keyframes slideInRight{ from{opacity:0; transform:translateX(24px);} to{opacity:1; transform:translateX(0);} }
@keyframes spin{ to{ transform:rotate(360deg); } }
@keyframes shimmer{ 0%{ background-position:-200px 0; } 100%{ background-position:200px 0; } }

/* ---------- LOGIN PAGE ---------- */
.login-wrap{
  min-height:100vh;
  display:flex;
}
.login-brand{
  flex:1 1 45%;
  background:
    radial-gradient(circle at 20% 20%, rgba(201,162,39,0.18), transparent 45%),
    radial-gradient(circle at 80% 80%, rgba(201,162,39,0.12), transparent 45%),
    linear-gradient(160deg, var(--navy) 0%, #081428 100%);
  display:flex;
  flex-direction:column;
  align-items:flex-start;
  justify-content:center;
  padding:60px;
  color:#EDE7D6;
  position:relative;
  overflow:hidden;
  animation:fadeIn .7s var(--ease);
}
.login-brand svg{ width:56px; height:56px; margin-bottom:22px; filter:drop-shadow(0 4px 10px rgba(0,0,0,.35)); }
.login-brand h1{ color:#fff; font-size:34px; margin-bottom:10px; letter-spacing:.3px; }
.login-brand h1 span{ color:var(--gold-light); }
.login-brand p{ color:#B9C3DA; font-size:15px; max-width:380px; line-height:1.6; }
.login-brand .deco{
  position:absolute; bottom:-60px; right:-60px; width:280px; height:280px;
  border:1px solid rgba(201,162,39,0.25); border-radius:50%;
}
.login-brand .deco2{
  position:absolute; top:-90px; right:60px; width:180px; height:180px;
  border:1px solid rgba(201,162,39,0.18); border-radius:50%;
}
.login-form-side{
  flex:1 1 55%;
  display:flex;
  align-items:center;
  justify-content:center;
  padding:20px;
  background:var(--cream);
}
.login-card{
  background:#fff;
  border-radius:var(--radius);
  box-shadow:var(--shadow);
  padding:44px 40px;
  width:100%;
  max-width:380px;
  border-top:5px solid var(--gold);
  animation:popIn .5s var(--ease);
}
.login-card .heading{ font-size:22px; font-weight:700; color:var(--navy); margin-bottom:4px; }
.login-card .tagline{ color:#6b7280; font-size:13px; margin-bottom:26px; }
.field{ text-align:left; margin-bottom:16px; }
.field label{ font-size:13px; font-weight:600; color:var(--navy); display:block; margin-bottom:5px; }
.field input{
  width:100%;
  padding:11px 13px;
  border:1px solid #DDD3B8;
  border-radius:8px;
  font-size:14px;
  background:var(--cream);
  color:var(--text);
  font-family:inherit;
  transition:border-color .2s, box-shadow .2s;
}
.field input:focus{ outline:none; border-color:var(--gold); box-shadow:0 0 0 3px rgba(201,162,39,0.2); }
.btn{
  display:inline-block;
  width:100%;
  padding:12px;
  background:var(--navy);
  color:#fff;
  border:none;
  border-radius:8px;
  font-size:15px;
  font-weight:600;
  cursor:pointer;
  font-family:inherit;
  transition:background .2s, transform .15s;
}
.btn:hover{ background:var(--navy-light); }
.btn:active{ transform:scale(.98); }
.error-msg{
  background:#FBEAE6; color:var(--danger); padding:10px 12px;
  border-radius:8px; font-size:13px; margin-bottom:16px; border:1px solid #F1C6BA;
  animation:fadeInUp .3s var(--ease);
}

/* ---------- APP LAYOUT ---------- */
.app{ display:flex; min-height:100vh; }
.nav-overlay{
  display:none; position:fixed; inset:0; background:rgba(15,34,71,0.5);
  z-index:59; opacity:0; transition:opacity .25s var(--ease);
}
.nav-overlay.show{ display:block; opacity:1; }

.sidebar{
  width:260px;
  background:var(--navy);
  color:#EDE7D6;
  padding:24px 18px;
  flex-shrink:0;
}
.sidebar .logo-row{ display:flex; align-items:center; gap:10px; margin-bottom:2px; }
.sidebar .logo-row svg{ width:30px; height:30px; }
.sidebar .logo{ font-size:21px; font-weight:700; color:#fff; }
.sidebar .logo span{ color:var(--gold-light); }
.sidebar .tagline{ font-size:11px; color:#9DAFCB; margin-bottom:26px; }
.sidebar .close-drawer{ display:none; }

.sidebar details{ margin-top:16px; }
.sidebar summary{
  color:var(--gold-light); font-size:11px; text-transform:uppercase;
  letter-spacing:1px; cursor:pointer; list-style:none; padding:4px 0;
  display:flex; justify-content:space-between; align-items:center;
}
.sidebar summary::-webkit-details-marker{ display:none; }
.sidebar summary::after{ content:'▾'; transition:transform .2s; font-size:10px; }
.sidebar details[open] summary::after{ transform:rotate(180deg); }
.sidebar ul{ list-style:none; padding:0; margin:8px 0 0; max-height:220px; overflow-y:auto; }
.sidebar ul::-webkit-scrollbar{ width:5px; }
.sidebar ul::-webkit-scrollbar-thumb{ background:rgba(255,255,255,0.15); border-radius:4px; }
.sidebar li{ margin-bottom:2px; }
.sidebar a.nav-link{
  display:flex; justify-content:space-between; color:#D9E0EE; padding:7px 10px;
  border-radius:6px; font-size:14px; transition:background .15s, color .15s;
}
.sidebar a.nav-link:hover, .sidebar a.nav-link.active{ background:var(--navy-light); color:#fff; }
.sidebar a.nav-link .count{ color:#8FA0C2; font-size:12px; }
.logout-link{ display:block; margin-top:30px; color:#E4C55E; font-size:13px; }

.hamburger{
  display:none; position:fixed; top:16px; left:16px; z-index:61;
  background:var(--navy); color:#fff; border:none; width:42px; height:42px;
  border-radius:9px; font-size:18px; cursor:pointer; box-shadow:var(--shadow);
}

.main{ flex:1; padding:28px 34px; min-width:0; }
.topbar{
  display:flex; justify-content:space-between; align-items:center;
  flex-wrap:wrap; gap:12px; margin-bottom:22px;
}
.topbar h2{ font-size:22px; }
.topbar .actions{ display:flex; gap:10px; flex-wrap:wrap; }
.btn-sm{
  padding:9px 16px; border-radius:8px; font-size:13px; font-weight:600;
  border:none; cursor:pointer; font-family:inherit; transition:background .2s, transform .15s, box-shadow .2s;
}
.btn-sm:active{ transform:scale(.96); }
.btn-navy{ background:var(--navy); color:#fff; }
.btn-navy:hover{ background:var(--navy-light); box-shadow:0 3px 10px rgba(15,34,71,.25); }
.btn-outline{ background:#fff; color:var(--navy); border:1.5px solid var(--navy); }
.btn-outline:hover{ background:var(--cream-alt); }

.search-bar{ margin-bottom:20px; }
.search-bar input{
  width:100%; padding:12px 16px; border-radius:9px; border:1px solid #DDD3B8;
  font-size:14px; background:#fff; font-family:inherit; transition:border-color .2s, box-shadow .2s;
}
.search-bar input:focus{ outline:none; border-color:var(--gold); box-shadow:0 0 0 3px rgba(201,162,39,0.15); }

.grid{
  display:grid;
  grid-template-columns:repeat(auto-fill,minmax(280px,1fr));
  gap:16px;
}
.card{
  background:#fff; border-radius:var(--radius); padding:18px;
  box-shadow:var(--shadow); border-left:4px solid var(--gold);
  display:flex; flex-direction:column; gap:8px;
  animation:fadeInUp .35s var(--ease) backwards;
  transition:transform .2s var(--ease), box-shadow .2s var(--ease);
}
.card:hover{ transform:translateY(-3px); box-shadow:0 10px 24px rgba(15,34,71,0.16); }
.card .name{ font-size:15px; font-weight:700; color:var(--navy); word-break:break-word; }
.card .name a{ transition:color .15s; }
.card .name a:hover{ color:var(--gold); }
.card .url{ font-size:12.5px; color:#5b6478; word-break:break-all; }
.card .meta{ display:flex; flex-wrap:wrap; gap:6px; margin-top:4px; }
.badge{ font-size:11px; padding:3px 9px; border-radius:20px; font-weight:600; }
.badge.cat{ background:var(--navy); color:#fff; }
.badge.tag{ background:var(--cream-alt); color:var(--navy); border:1px solid #E3D8B8; }
.badge.status-ok{ background:#E4F3E8; color:var(--ok); }
.badge.status-broken{ background:#FBEAE6; color:var(--danger); }
.badge.status-unknown{ background:#EFEFEF; color:#777; }
.card .row-actions{ display:flex; justify-content:space-between; align-items:center; margin-top:6px; gap:10px; }
.card .row-actions .left-links{ display:flex; gap:12px; }
.card .row-actions a{ font-size:12px; font-weight:600; transition:color .15s; }
.card .gh-link{ color:var(--navy); }
.icon-btn{
  background:none; border:none; font-size:12px; cursor:pointer; font-weight:600;
  transition:color .15s, transform .15s;
}
.icon-btn:active{ transform:scale(.9); }
.edit-btn{ color:var(--navy); }
.edit-btn:hover{ color:var(--gold); }
.del-btn{ color:var(--danger); }
.del-btn:hover{ color:#8a2e1c; }

/* modal */
.modal-overlay{
  display:none; position:fixed; inset:0; background:rgba(15,34,71,0.45);
  align-items:center; justify-content:center; padding:16px; z-index:70;
  opacity:0; transition:opacity .2s var(--ease);
}
.modal-overlay.open{ display:flex; opacity:1; }
.modal{
  background:#fff; border-radius:var(--radius); padding:26px; width:100%; max-width:420px;
  max-height:90vh; overflow-y:auto; border-top:5px solid var(--gold);
  animation:popIn .3s var(--ease);
}
.modal h3{ margin-bottom:16px; }
.modal .field{ margin-bottom:14px; }
.modal .field input, .modal .field select{
  width:100%; padding:10px 12px; border:1px solid #DDD3B8; border-radius:7px; font-size:14px;
  font-family:inherit; transition:border-color .2s, box-shadow .2s;
}
.modal .field input:focus{ outline:none; border-color:var(--gold); box-shadow:0 0 0 3px rgba(201,162,39,0.15); }
.modal-actions{ display:flex; gap:10px; margin-top:18px; }
.modal-actions .btn-sm{ flex:1; }
.empty-state{ text-align:center; padding:60px 20px; color:#8a8172; animation:fadeIn .4s var(--ease); }
.toast{
  position:fixed; bottom:20px; right:20px; background:var(--navy); color:#fff;
  padding:12px 18px; border-radius:8px; font-size:13px; box-shadow:var(--shadow);
  display:none; z-index:100;
}
.toast.show{ display:block; animation:slideInRight .3s var(--ease); }
.spinner{
  width:14px; height:14px; border:2px solid rgba(255,255,255,.4); border-top-color:#fff;
  border-radius:50%; display:inline-block; animation:spin .7s linear infinite; margin-right:6px; vertical-align:-2px;
}

/* responsive */
@media (max-width: 860px){
  .hamburger{ display:block; }
  .app{ flex-direction:column; }
  .sidebar{
    position:fixed; top:0; left:0; height:100vh; z-index:60; width:78%; max-width:300px;
    transform:translateX(-105%); transition:transform .28s var(--ease); overflow-y:auto;
    box-shadow:8px 0 24px rgba(0,0,0,0.25);
  }
  .sidebar.open{ transform:translateX(0); }
  .sidebar .close-drawer{
    display:block; position:absolute; top:16px; right:16px; background:none; border:none;
    color:#EDE7D6; font-size:20px; cursor:pointer;
  }
  .main{ padding:78px 18px 24px; }
  .login-brand{ display:none; }
}
@media (max-width: 480px){
  .grid{ grid-template-columns:1fr; }
  .topbar{ flex-direction:column; align-items:flex-start; }
  .topbar .actions{ width:100%; }
  .topbar .actions .btn-sm{ flex:1; }
  .login-card{ padding:32px 24px; }
}
</style>
</head>
<body>

<?php if (!is_logged_in()): ?>
<!-- =================== LOGIN PAGE =================== -->
<div class="login-wrap">
  <div class="login-brand">
    <div class="deco"></div>
    <div class="deco2"></div>
    <?= $logoSvg ?>
    <h1>Vault<span>mark</span></h1>
    <p>Bookmarks vanish when browsers crash, sync breaks, or a device gets wiped. Vaultmark keeps every link, organized by category and tag, in one place only you control.</p>
  </div>
  <div class="login-form-side">
    <div class="login-card">
      <div class="heading">Welcome back</div>
      <div class="tagline">Log in to your vault</div>
      <?php if (!empty($login_error)): ?>
        <div class="error-msg"><?= htmlspecialchars($login_error) ?></div>
      <?php endif; ?>
      <form method="post" action="?action=login" autocomplete="off">
        <div class="field">
          <label>Username</label>
          <input type="text" name="username" required autofocus autocomplete="username">
        </div>
        <div class="field">
          <label>Password</label>
          <input type="password" name="password" required autocomplete="current-password">
        </div>
        <button class="btn" type="submit">Log In</button>
      </form>
    </div>
  </div>
</div>

<?php else: ?>
<!-- =================== DASHBOARD =================== -->
<button class="hamburger" id="hamburgerBtn" aria-label="Open menu">☰</button>
<div class="nav-overlay" id="navOverlay"></div>
<div class="app">
  <nav class="sidebar" id="sidebar">
    <button class="close-drawer" id="closeDrawer" aria-label="Close menu">✕</button>
    <div class="logo-row"><?= $logoSvg ?><span class="logo">Vault<span>mark</span></span></div>
    <div class="tagline">Your bookmarks, safe forever.</div>

    <ul>
      <li><a class="nav-link active" href="#" data-filter-cat="All">All Bookmarks <span class="count"><?= count($bookmarks) ?></span></a></li>
    </ul>

    <details open>
      <summary>Categories</summary>
      <ul id="categoryList">
        <?php foreach ($categories as $cat):
          $n = count(array_filter($bookmarks, fn($b) => $b['category'] === $cat)); ?>
          <li><a class="nav-link" href="#" data-filter-cat="<?= htmlspecialchars($cat) ?>"><?= htmlspecialchars($cat) ?> <span class="count"><?= $n ?></span></a></li>
        <?php endforeach; ?>
        <?php if (empty($categories)): ?><li style="color:#8FA0C2;font-size:13px;">No categories yet</li><?php endif; ?>
      </ul>
    </details>

    <details open>
      <summary>Tags</summary>
      <ul id="tagList">
        <?php foreach ($allTags as $tag):
          $n = count(array_filter($bookmarks, fn($b) => in_array($tag, $b['tags']))); ?>
          <li><a class="nav-link" href="#" data-filter-tag="<?= htmlspecialchars($tag) ?>"><?= htmlspecialchars($tag) ?> <span class="count"><?= $n ?></span></a></li>
        <?php endforeach; ?>
        <?php if (empty($allTags)): ?><li style="color:#8FA0C2;font-size:13px;">No tags yet</li><?php endif; ?>
      </ul>
    </details>

    <a class="logout-link" href="?action=logout">Log out (<?= htmlspecialchars($_SESSION['user']) ?>)</a>
  </nav>

  <main class="main">
    <div class="topbar">
      <h2 id="viewTitle">All Bookmarks</h2>
      <div class="actions">
        <button class="btn-sm btn-outline" id="crawlBtn">Check Links</button>
        <button class="btn-sm btn-outline" id="importBtn">Import</button>
        <button class="btn-sm btn-navy" id="addBtn">+ Add Bookmark</button>
      </div>
    </div>

    <div class="search-bar">
      <input type="text" id="searchInput" placeholder="Search by name, URL, tag or category...">
    </div>

    <div class="grid" id="grid"></div>
    <div class="empty-state" id="emptyState" style="display:none;">No bookmarks found. Add your first one!</div>
  </main>
</div>

<!-- Add / Edit Bookmark Modal -->
<div class="modal-overlay" id="addModalOverlay">
  <div class="modal">
    <h3 id="bookmarkModalTitle">Add Bookmark</h3>
    <form id="addForm">
      <input type="hidden" name="id" id="bookmarkId">
      <div class="field"><label>Name *</label><input type="text" name="name" required></div>
      <div class="field"><label>URL *</label><input type="url" name="url" placeholder="https://example.com" required></div>
      <div class="field"><label>GitHub (optional)</label><input type="url" name="github" placeholder="https://github.com/user/repo"></div>
      <div class="field"><label>Category</label><input type="text" name="category" list="catOptions" placeholder="e.g. Development" value="Uncategorized">
        <datalist id="catOptions"><?php foreach ($categories as $c): ?><option value="<?= htmlspecialchars($c) ?>"><?php endforeach; ?></datalist>
      </div>
      <div class="field"><label>Tags (comma-separated)</label><input type="text" name="tags" placeholder="php, tools, reference"></div>
      <div class="modal-actions">
        <button type="button" class="btn-sm btn-outline" id="cancelAdd">Cancel</button>
        <button type="submit" class="btn-sm btn-navy" id="saveBookmarkBtn">Save Bookmark</button>
      </div>
    </form>
  </div>
</div>

<!-- Import Modal -->
<div class="modal-overlay" id="importModalOverlay">
  <div class="modal">
    <h3>Import Browser Bookmarks</h3>
    <p style="font-size:13px;color:#6b7280;margin-bottom:14px;">
      Export your bookmarks from Chrome, Firefox, Edge, Safari or Brave as an HTML file
      (Bookmark Manager &rarr; Export Bookmarks), then upload it here.
    </p>
    <form id="importForm" enctype="multipart/form-data">
      <div class="field"><input type="file" name="file" accept=".html,.htm" required></div>
      <div class="modal-actions">
        <button type="button" class="btn-sm btn-outline" id="cancelImport">Cancel</button>
        <button type="submit" class="btn-sm btn-navy">Import</button>
      </div>
    </form>
  </div>
</div>

<div class="toast" id="toast"></div>

<script>
const CSRF = "<?= csrf_token() ?>";
let ALL_BOOKMARKS = <?= json_encode($bookmarks) ?>;
let activeCat = 'All';
let activeTag = null;
let editingId = null;

const grid = document.getElementById('grid');
const emptyState = document.getElementById('emptyState');
const viewTitle = document.getElementById('viewTitle');
const toast = document.getElementById('toast');

function showToast(msg) {
  toast.textContent = msg;
  toast.classList.remove('show'); void toast.offsetWidth;
  toast.classList.add('show');
  setTimeout(() => toast.classList.remove('show'), 2800);
}

function escapeHtml(str) {
  const d = document.createElement('div');
  d.textContent = str ?? '';
  return d.innerHTML;
}

function statusBadge(status) {
  if (status === 'ok') return '<span class="badge status-ok">✓ live</span>';
  if (status === 'broken') return '<span class="badge status-broken">✗ broken</span>';
  return '<span class="badge status-unknown">? unchecked</span>';
}

function render() {
  const search = document.getElementById('searchInput').value.toLowerCase().trim();
  let items = ALL_BOOKMARKS.filter(b => {
    if (activeCat !== 'All' && b.category !== activeCat) return false;
    if (activeTag && !b.tags.includes(activeTag)) return false;
    if (search) {
      const hay = (b.name + ' ' + b.url + ' ' + b.category + ' ' + b.tags.join(' ')).toLowerCase();
      if (!hay.includes(search)) return false;
    }
    return true;
  });

  grid.innerHTML = '';
  emptyState.style.display = items.length ? 'none' : 'block';

  items.forEach((b, i) => {
    const card = document.createElement('div');
    card.className = 'card';
    card.style.animationDelay = (Math.min(i, 12) * 0.03) + 's';
    card.innerHTML = `
      <div class="name"><a href="${escapeHtml(b.url)}" target="_blank" rel="noopener">${escapeHtml(b.name)}</a></div>
      <div class="url">${escapeHtml(b.url)}</div>
      <div class="meta">
        <span class="badge cat">${escapeHtml(b.category)}</span>
        ${statusBadge(b.status)}
        ${b.tags.map(t => `<span class="badge tag">#${escapeHtml(t)}</span>`).join('')}
      </div>
      <div class="row-actions">
        <span class="left-links">
          ${b.github ? `<a class="gh-link" href="${escapeHtml(b.github)}" target="_blank" rel="noopener">GitHub &rarr;</a>` : ''}
          <button class="icon-btn edit-btn" data-id="${b.id}">Edit</button>
        </span>
        <button class="icon-btn del-btn" data-id="${b.id}">Delete</button>
      </div>
    `;
    grid.appendChild(card);
  });

  grid.querySelectorAll('.del-btn').forEach(btn => btn.addEventListener('click', () => deleteBookmark(btn.dataset.id)));
  grid.querySelectorAll('.edit-btn').forEach(btn => btn.addEventListener('click', () => openEdit(btn.dataset.id)));
}

async function deleteBookmark(id) {
  if (!confirm('Delete this bookmark?')) return;
  const fd = new FormData();
  fd.append('csrf', CSRF);
  fd.append('id', id);
  const res = await fetch('?action=delete', { method: 'POST', body: fd });
  const data = await res.json();
  if (data.ok) {
    ALL_BOOKMARKS = ALL_BOOKMARKS.filter(b => b.id !== id);
    render();
    showToast('Bookmark deleted.');
  } else {
    showToast(data.error || 'Delete failed.');
  }
}

// Add / Edit modal
const addModal = document.getElementById('addModalOverlay');
const addForm = document.getElementById('addForm');
const modalTitle = document.getElementById('bookmarkModalTitle');
const saveBtn = document.getElementById('saveBookmarkBtn');

function openAdd() {
  editingId = null;
  addForm.reset();
  document.getElementById('bookmarkId').value = '';
  modalTitle.textContent = 'Add Bookmark';
  saveBtn.textContent = 'Save Bookmark';
  addModal.classList.add('open');
}

function openEdit(id) {
  const b = ALL_BOOKMARKS.find(x => x.id === id);
  if (!b) return;
  editingId = id;
  addForm.reset();
  document.getElementById('bookmarkId').value = b.id;
  addForm.name.value = b.name;
  addForm.url.value = b.url;
  addForm.github.value = b.github || '';
  addForm.category.value = b.category;
  addForm.tags.value = b.tags.join(', ');
  modalTitle.textContent = 'Edit Bookmark';
  saveBtn.textContent = 'Update Bookmark';
  addModal.classList.add('open');
}

document.getElementById('addBtn').onclick = openAdd;
document.getElementById('cancelAdd').onclick = () => addModal.classList.remove('open');
addForm.addEventListener('submit', async e => {
  e.preventDefault();
  const fd = new FormData(e.target);
  fd.append('csrf', CSRF);
  const endpoint = editingId ? '?action=edit' : '?action=add';
  const res = await fetch(endpoint, { method: 'POST', body: fd });
  const data = await res.json();
  if (data.ok) {
    if (editingId) {
      ALL_BOOKMARKS = ALL_BOOKMARKS.map(b => b.id === editingId ? data.bookmark : b);
      showToast('Bookmark updated.');
    } else {
      ALL_BOOKMARKS.push(data.bookmark);
      showToast('Bookmark added.');
    }
    addModal.classList.remove('open');
    render();
  } else {
    showToast(data.error || 'Failed to save bookmark.');
  }
});

// sidebar filter clicks
function bindFilterLinks() {
  document.querySelectorAll('[data-filter-cat]').forEach(el => {
    el.addEventListener('click', e => {
      e.preventDefault();
      activeCat = el.dataset.filterCat;
      activeTag = null;
      document.querySelectorAll('.nav-link').forEach(n => n.classList.remove('active'));
      el.classList.add('active');
      viewTitle.textContent = activeCat === 'All' ? 'All Bookmarks' : activeCat;
      render();
      closeDrawer();
    });
  });
  document.querySelectorAll('[data-filter-tag]').forEach(el => {
    el.addEventListener('click', e => {
      e.preventDefault();
      activeTag = el.dataset.filterTag;
      activeCat = 'All';
      document.querySelectorAll('.nav-link').forEach(n => n.classList.remove('active'));
      el.classList.add('active');
      viewTitle.textContent = '#' + activeTag;
      render();
      closeDrawer();
    });
  });
}
bindFilterLinks();

document.getElementById('searchInput').addEventListener('input', render);

// Import modal
const importModal = document.getElementById('importModalOverlay');
document.getElementById('importBtn').onclick = () => importModal.classList.add('open');
document.getElementById('cancelImport').onclick = () => importModal.classList.remove('open');
document.getElementById('importForm').addEventListener('submit', async e => {
  e.preventDefault();
  const fd = new FormData(e.target);
  fd.append('csrf', CSRF);
  showToast('Importing...');
  const res = await fetch('?action=import', { method: 'POST', body: fd });
  const data = await res.json();
  if (data.ok) {
    importModal.classList.remove('open');
    e.target.reset();
    showToast(`Imported ${data.imported} new bookmark(s) of ${data.total_found} found.`);
    location.reload();
  } else {
    showToast(data.error || 'Import failed.');
  }
});

// Crawl / link check
document.getElementById('crawlBtn').addEventListener('click', async (e) => {
  const btn = e.currentTarget;
  const original = btn.textContent;
  btn.innerHTML = '<span class="spinner"></span>Checking...';
  btn.disabled = true;
  const cat = encodeURIComponent(activeCat);
  try {
    const res = await fetch(`?action=crawl&cat=${cat}`);
    const data = await res.json();
    if (data.ok) {
      ALL_BOOKMARKS = data.bookmarks;
      render();
      showToast(`Checked ${data.checked} link(s) in "${data.category}".`);
    } else {
      showToast('Link check failed.');
    }
  } finally {
    btn.textContent = original;
    btn.disabled = false;
  }
});

// Mobile off-canvas nav
const sidebar = document.getElementById('sidebar');
const overlay = document.getElementById('navOverlay');
function openDrawer() { sidebar.classList.add('open'); overlay.classList.add('show'); }
function closeDrawer() { sidebar.classList.remove('open'); overlay.classList.remove('show'); }
document.getElementById('hamburgerBtn')?.addEventListener('click', openDrawer);
document.getElementById('closeDrawer')?.addEventListener('click', closeDrawer);
overlay?.addEventListener('click', closeDrawer);

render();
</script>
<?php endif; ?>
</body>
</html>
