# 🔖 Vaultmark

**Your bookmarks, safe forever.**

Vaultmark is a lightweight, single-file PHP bookmark manager built to solve a simple but annoying problem: browsers lose bookmarks. Profiles get wiped, sync breaks, devices get reset — and years of saved links disappear. Vaultmark keeps them in one portable place you control, with no database and no dependencies beyond PHP itself.

![PHP](https://img.shields.io/badge/PHP-7.4%2B-777BB4?logo=php&logoColor=white)
![License](https://img.shields.io/badge/license-MIT-blue)
![Storage](https://img.shields.io/badge/storage-JSON-C9A227)
![No Database](https://img.shields.io/badge/database-none%20required-0F2247)

---

## ✨ Features

- **Single PHP file.** Drop `index.php` on any PHP host and you're running — no build step, no Composer, no database.
- **JSON storage.** Bookmarks and users live in flat JSON files under a locked-down `data/` folder.
- **Login-protected dashboard** with a polished cream / navy / gold theme, Noto Sans throughout, subtle motion (card lift, modal pop-in, staggered grid load), and a custom SVG bookmark-shield logo used as both the in-app mark and the favicon.
- **Categories & Tags.** Organize and filter bookmarks from the sidebar, plus live search.
- **Add, edit, and delete bookmarks** — name, URL, GitHub link (auto-detected from the URL if left blank), tags, category.
- **Import from any browser.** Upload a bookmarks export from Chrome, Firefox, Edge, Safari, or Brave — they all use the same Netscape Bookmark HTML format. Folders become categories, duplicate URLs are skipped automatically.
- **Broken-link checker.** Hit the crawl endpoint (`?action=crawl&cat=CategoryName`) or click "Check Links" to have Vaultmark verify every link in a category via cURL and flag it as live or broken.
- **CSRF-protected, session-based auth** with brute-force lockout on repeated failed logins.

---

## 📦 Installation

1. Clone or download this repo.
   ```bash
   git clone https://github.com/psvineet/vaultmark.git
   ```
2. Upload `index.php` to any PHP 7.4+ host (Apache or Nginx) with the `curl` and `dom` extensions enabled — both are on by default in almost every PHP install.
3. Visit `index.php` in your browser. On first load it automatically creates a `data/` folder next to it containing:
   - `users.json` — seeded with a random generated password for the `admin` account
   - `INITIAL_PASSWORD.txt` — the one-time generated admin password (never shown in the UI itself, for security)
   - `bookmarks.json` — starts empty
   - `attempts.json` — tracks failed logins for brute-force lockout
   - `.htaccess` — blocks direct web access to the folder (Apache only)
4. Open `data/INITIAL_PASSWORD.txt` via SFTP/file manager to get your first login, then **delete that file** once you've logged in and changed your password.

That's it — no database setup, no migrations, no config files to edit.

---

## 🚀 Usage

### Adding bookmarks
Click **+ Add Bookmark** and fill in name, URL, an optional GitHub link, category, and comma-separated tags. If the URL is a `github.com` link and you leave the GitHub field blank, Vaultmark fills it in automatically.

### Importing from your browser
Export your existing bookmarks:

| Browser | Path |
|---|---|
| Chrome / Brave / Edge | `⋮` → Bookmarks → Bookmark Manager → `⋮` → Export Bookmarks |
| Firefox | Bookmarks → Manage Bookmarks → Import and Backup → Export Bookmarks to HTML |
| Safari | File → Export → Bookmarks |

Then click **Import** in Vaultmark and upload the exported `.html` file. Folder structure is preserved as categories, and anything already in your vault (matched by URL) is skipped.

### Checking for dead links
Click **Check Links** (or filter to a category first to scope the check) to have Vaultmark crawl each URL and mark it `✓ live` or `✗ broken` right on the card.

### API-style endpoints
| Endpoint | Method | Description |
|---|---|---|
| `?action=login` | POST | Authenticate |
| `?action=logout` | GET | End session |
| `?action=list` | GET | Return all bookmarks as JSON |
| `?action=add` | POST | Add a bookmark |
| `?action=delete` | POST | Delete a bookmark by `id` |
| `?action=import` | POST (multipart) | Import a browser bookmarks HTML export |
| `?action=crawl&cat=CategoryName` | GET | Check link status for a category (use `cat=All` for everything) |

All authenticated endpoints require a valid session; all POST endpoints require a CSRF token issued to the logged-in session.

---

## 🔒 Security

- **First login uses a randomly generated password**, written once to `data/INITIAL_PASSWORD.txt` — never rendered on the login page or anywhere in the UI. Retrieve it via SFTP/file manager, log in, then delete that file.
- No credentials of any kind are shown on the login page itself.
- **Brute-force lockout:** after 5 failed logins for the same username+IP within 15 minutes, that combination is locked out for 15 minutes. Failed logins get a small artificial delay and a generic "invalid username or password" message (doesn't reveal whether the username exists). Tune this via `MAX_ATTEMPTS`, `ATTEMPT_WINDOW`, `LOCKOUT_TIME` near the top of `index.php`.
- Session ID is regenerated on every successful login (session-fixation guard).
- The `data/` folder ships with an `.htaccess` denying direct access — this only works on **Apache**. If you're on **Nginx**, add a rule to block `/data/` yourself, e.g.:
  ```nginx
  location ~ ^/data/ {
      deny all;
      return 404;
  }
  ```
- For extra safety in production, move `data/` above the web root entirely and update the `DATA_DIR` constant near the top of `index.php` to point to the new path.
- All write actions are CSRF-token protected, and JSON writes use file locking (`flock`) to avoid corruption under concurrent requests.

---

## 🗂 Project structure

```
vaultmark/
├── index.php               # the entire application
└── data/                   # auto-created on first run
    ├── users.json           # credentials (hashed)
    ├── INITIAL_PASSWORD.txt # one-time generated admin password — delete after first login
    ├── bookmarks.json        # your bookmark vault
    ├── attempts.json          # brute-force lockout tracking
    └── .htaccess               # blocks direct access (Apache)
```

---

## 🛠 Requirements

- PHP 7.4 or newer
- `curl` extension (for the link-checker)
- `dom` extension (for parsing browser bookmark exports)
- Apache (for the bundled `.htaccess`) or any server where you can block a folder manually

---

## 🤝 Contributing

Issues and pull requests are welcome. If you're adding a feature, try to keep the single-file philosophy intact where reasonable, or clearly document why a split is needed.

---

## 📄 License

MIT — do whatever you like with it, just don't blame me if you lose your bookmarks to something *other* than a browser this time.
