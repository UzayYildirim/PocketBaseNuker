![PocketBase Nuker Logo](https://i.ibb.co/mFNLfXZV/image.png)

## PocketBase Nuker ☢️

An utility to clean-up or wipe a PocketBase database *from the command line* safely, quickly, and with lots of feedback.

```text
⚠️ By using or modifying “PocketBase Nuker” (pbnuker.py) you acknowledge and agree that the author and distributor provide this tool “as-is” without warranty of any kind, express or implied, including but not limited to warranties of merchantability, fitness for a particular purpose, non-infringement or freedom from defects; in no event shall the author, contributors or any affiliated parties be liable for any direct, indirect, incidental, special, consequential or punitive damages whatsoever (including, without limitation, data loss, downtime, loss of profits or business interruption) arising out of the use or inability to use this software, even if advised of the possibility of such damages.
```

`pbnuker.py` is a single-file Python script. Run it when you need to:

* delete all records in **one** collection (by filter, timestamp, or explicit IDs)
* empty **every** custom collection (system tables stay)
* **drop** all collections except your auth tables (`users`, `_superusers`, `_admins` by default)

It supports dry-runs, synchronous deletes with retry/back-off, saved configuration, and a final summary table.

---

### Installation

```bash
# create a virtual env 
python -m venv .venv
source .venv/bin/activate

# install dependencies
pip install requests    # required
pip install rich        # optional but prettier output
```

Python 3.8 or newer is required.

---

### Quick look

```text
python pbnuker.py [global flags] <subcommand> [subcommand flags]
# e.g. python pbnuker.py -u http://127.0.0.1:8090 purge-collection orders --dry-run
# global flags (`--url`, `--email`, etc.) may appear before or after the subcommand
```

| Flag                  | Expects                            | Required? | Purpose / Notes                                      |
| --------------------- | ---------------------------------- | --------- | ---------------------------------------------------- |
| `-u`, `--url`         | URL (e.g. `http://127.0.0.1:8090`) | Optional  | PocketBase server address                            |
| `-e`, `--email`       | string (email)                     | Optional¹ | Login e-mail; required if no `--token`               |
| `-p`, `--password`    | string                             | Optional¹ | Login password; required if no `--token`             |
| `-t`, `--token`       | string                             | Optional  | Admin API token (alternative to email/password)      |
| `--clear-config`      | -                                | Optional  | Delete saved settings (`pbnuker.ini`)                |
| `--login-collections` | list (`users _superusers _admins`) | Optional  | Auth collections to try, first successful wins       |
| `--timeout`           | int seconds (default 15)           | Optional  | Per-request HTTP timeout                             |
| `--retries`           | int (default 3)                    | Optional  | Number of HTTP retries on failure                    |
| `--backoff`           | float (default 0.6)                | Optional  | Initial retry backoff delay (seconds)                |
| `--page-size`         | int (default 100)                  | Optional  | Records per page when listing (capped at 100)        |
| `--insecure`          | -                                | Optional  | Skip TLS certificate verification                    |
| `--verbose`           | -                                | Optional  | Extra progress / debug lines                         |
| `--dry-run`           | -                                | Optional  | Show what would happen, don’t delete or drop         |
| `-y`, `--yes`         | -                                | Optional  | Skip the confirmation prompt                         |
| `--log-file`          | path                               | Optional  | Custom log file path                                 |
| `--storage-path`      | path                               | Optional² | Custom directory for file cleanup (used with `nuke`) |
| `--cleanup-files`     | -                                | Optional² | Also delete uploaded files when running `nuke`       |

¹ Email/password are prompted if neither `--token` nor both `--email` and `--password` are provided.

² Only used by the `nuke` subcommand.

---

### Recipes

| What you want to do                                           | Command                                                                                                                       |
| ------------------------------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------- |
| **Delete everything** in collection `orders`                  | `python pbnuker.py purge-collection orders -u http://localhost:8090 -e you@demo.com -p pass123`                               |
| Delete only records where `status = 'CANCELLED'`              | `python pbnuker.py purge-collection orders -u http://localhost:8090 -e you@demo.com -p pass123 -f "status='CANCELLED'"`       |
| Delete records created **before 1 May 2025**                  | `python pbnuker.py purge-collection logs -u http://localhost:8090 -e you@demo.com -p pass123 --before 2025-05-01`             |
| Delete **exact IDs**                                          | `python pbnuker.py purge-collection drafts -u http://localhost:8090 -e you@demo.com -p pass123 --ids a1b2 c3d4 e5f6`          |
| **Empty every** custom collection                             | `python pbnuker.py purge-all -u http://localhost:8090 -e you@demo.com -p pass123`                                             |
| **Nuke** the database (drop collections) but keep auth tables | `python pbnuker.py nuke -u http://localhost:8090 -e you@demo.com -p pass123 --auth users _superusers _admins`                 |
| **Nuke + file cleanup**                                       | `python pbnuker.py nuke -u http://localhost:8090 -e you@demo.com -p pass123 --cleanup-files --storage-path ./pb_data/storage` |
| **Preview** first, then destroy                               | `python pbnuker.py purge-all ... --dry-run` <br> `python pbnuker.py nuke ... --dry-run`                                       |

---

### Exit codes (for CLI)

| Code    | Meaning                                      |
| ------- | -------------------------------------------- |
| **0**   | success                                      |
| **1**   | bad CLI flags or user validation error       |
| **2**   | PocketBase / network problem (after retries) |
| **130** | interrupted with Ctrl-C                      |
| **99**  | unexpected / unhandled error                 |

---

### Safety tips

* Always start with `--dry-run` on production. The summary table shows how many records or collections **would** be affected.
* Take a PocketBase backup before real deletion.
* Adjust `--page-size`, `--retries`, or `--backoff` for your server’s scale and network conditions.
* `--verbose` is your friend when debugging filters or network glitches.
* Use `--insecure` **only** on local labs with self-signed certificates.

---

### Configuration

After a successful non-dry run, the script saves your settings to `pbnuker.ini`:

* **DEFAULT**: `url`, `email`, `password`, `token`, `login_collections`, `timeout`, `retries`, `backoff`, `page_size`, `insecure`, `verbose`, `cmd`, `log_file`
* **purge-collection**: `collection`, `filter`, `before`, `ids`
* **nuke**: `auth`, `cleanup_files`, `storage_path`

On subsequent runs with no meaningful arguments you'll be shown the saved configuration and asked whether to reuse it. Use `--clear-config` to delete `pbnuker.ini` and start fresh.

---

### License

This project is licensed under the MIT License.

---

# 🌟 Support

If you find this project helpful, please consider:

* Giving it a star ⭐
* [Buying me a coffee](https://buymeacoffee.com/uzayyildirim)
