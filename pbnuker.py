# ────────────────────────────────────────────────────────────────────────
# PocketBase Cleanup Utility (PocketBase Nuker)  •  Uzay Yildirim
# ────────────────────────────────────────────────────────────────────────
#  MIT-licensed.  No deps except requests (mandatory) and rich (optional).
#
# By using or modifying "PocketBase Nuker" (pbnuker.py) you acknowledge and
# agree that the author and distributor provide this tool "as-is" without
# warranty of any kind, express or implied, including but not limited
# to warranties of merchantability, fitness for a particular purpose,
# non-infringement or freedom from defects; in no event shall the author,
# contributors or any affiliated parties be liable for any direct,
# indirect, incidental, special, consequential or punitive damages whatsoever
# (including, without limitation, data loss, downtime, loss of profits or
# business interruption) arising out of the use or inability to use this
# software, even if advised of the possibility of such damages.
# ────────────────────────────────────────────────────────────────────────
"""Delete or drop PocketBase data from the command line."""

from __future__ import annotations

import argparse
import configparser
import datetime as dt
import json
import logging
import os
import platform
import random
import re
import signal
import sys
import time
from contextlib import suppress
from typing import List, Tuple, Optional

# ───── Python version check (now just 3.8+ needed) ─────────────────────
if sys.version_info < (3, 8):
    print("ERROR: Python 3.8+ required")
    sys.exit(1)

# ───── Optional rich niceties ───────────────────────────────────────────
try:
    from rich.console import Console
    from rich.table import Table

    RICH = True
    console: Console = Console()
except ImportError:
    RICH = False

    class _Console:
        def print(self, *a, **kw):
            print(*a)

        def rule(self, *a, **kw):
            print("-" * 60)

    console = _Console()  # type: ignore
# ────────────────────────────────────────────────────────────────────────

import requests

# ───── PocketBase API routes ────────────────────────────────────────────
API_COLLS = "/api/collections"
LOGIN_ROUTE = "/api/collections/{}/auth-with-password"
RECORDS_ROUTE = "/api/collections/{}/records"
RECORD_ROUTE = "/api/collections/{}/records/{}"

# ╔═══════════════════════════════════════════════════════════════════════
# ║  Exceptions & helpers
# ╚═══════════════════════════════════════════════════════════════════════
class PBError(RuntimeError):
    """Generic PocketBase error."""

class FilterParseError(ValueError):
    """Filter expression parsing error."""

class HTTPError(PBError):
    """HTTP response not OK."""
    def __init__(self, resp: requests.Response, ctx: str = ""):
        msg = f"{ctx}: {resp.status_code} {resp.reason}"
        with suppress(json.JSONDecodeError, ValueError):
            js = resp.json()
            # Try multiple error message keys
            error_msg = None
            if isinstance(js, dict):
                for key in ['message', 'error', 'details']:
                    if js.get(key):
                        error_msg = js[key]
                        break
                # Check nested data
                if not error_msg and 'data' in js:
                    data = js['data']
                    if isinstance(data, dict):
                        for key in ['message', 'error']:
                            if data.get(key):
                                error_msg = data[key]
                                break
            if error_msg:
                msg += f" — {error_msg}"
        super().__init__(msg)
        self.status = resp.status_code
        self.body   = resp.text

def die(msg: str, code: int = 1):
    console.print(f"[bold red]ERROR:[/bold red] {msg}" if RICH else f"ERROR: {msg}")
    sys.exit(code)

def prompt_yes_no(prompt: str, auto_yes: bool = False) -> bool:
    """Prompt for yes/no confirmation. In non-TTY environments, respect auto_yes flag."""
    if auto_yes:
        return True
    if not sys.stdin.isatty():
        # In automated environments, default to no for safety
        print(f"{prompt} [y/N] (non-interactive: defaulting to 'no')")
        return False
    response = input(f"{prompt} [y/N] ").strip().lower()
    return response in ("y", "yes")

def setup_logging(log_file: Optional[str] = None, verbose: bool = False) -> logging.Logger:
    """Setup logging to file and console."""
    logger = logging.getLogger('pbnuker')
    logger.setLevel(logging.INFO)
    
    # Clear existing handlers
    logger.handlers.clear()
    
    # File handler
    if log_file:
        try:
            # Create directory only if log_file contains a path
            log_dir = os.path.dirname(log_file)
            if log_dir:  # Only create directory if there is one
                try:
                    os.makedirs(log_dir, exist_ok=True)
                except (OSError, IOError, PermissionError) as dir_err:
                    # Directory creation failed, but continue to try file creation
                    # in case the directory already exists or is accessible
                    print(f"Warning: Could not create log directory '{log_dir}': {dir_err}")
            
            fh = logging.FileHandler(log_file)
            fh.setLevel(logging.INFO)
            fh.setFormatter(logging.Formatter(
                '%(asctime)s - %(levelname)s - %(message)s'
            ))
            logger.addHandler(fh)
        except (OSError, IOError, PermissionError) as e:
            # Fallback to console-only logging if file logging fails
            print(f"Warning: Could not create log file '{log_file}': {e}")
            print("Continuing with console-only logging...")
    
    # Console handler - show INFO in verbose mode, WARNING+ otherwise
    ch = logging.StreamHandler()
    ch.setLevel(logging.INFO if verbose else logging.WARNING)
    ch.setFormatter(logging.Formatter('%(levelname)s: %(message)s'))
    logger.addHandler(ch)
    
    return logger

# ╔═══════════════════════════════════════════════════════════════════════
# ║  Configuration Management
# ╚═══════════════════════════════════════════════════════════════════════
CONFIG_FILE = "pbnuker.ini"

def load_config() -> configparser.ConfigParser:
    """Load configuration from file if it exists."""
    config = configparser.ConfigParser()
    if os.path.exists(CONFIG_FILE):
        config.read(CONFIG_FILE)
    return config

def save_config(args: argparse.Namespace):
    """Save current arguments to config file for future runs."""
    config = configparser.ConfigParser()
    config['DEFAULT'] = {
        'url': args.url or '',
        'email': args.email or '',
        'password': args.password or '',
        'token': args.token or '',
        'login_collections': ' '.join(args.login_collections),
        'timeout': str(args.timeout),
        'retries': str(args.retries),
        'backoff': str(args.backoff),
        'page_size': str(args.page_size),
        'insecure': str(args.insecure),
        'verbose': str(args.verbose),
        'cmd': args.cmd,
    }
    
    # Save subcommand-specific args
    if args.cmd == 'purge-collection':
        config['purge-collection'] = {
            'collection': getattr(args, 'collection', ''),
            'filter': getattr(args, 'filter', '') or '',
            'before': getattr(args, 'before', '') or '',
        }
    elif args.cmd == 'purge-all':
        config['purge-all'] = {
        }
    elif args.cmd == 'nuke':
        config['nuke'] = {
            'auth': ' '.join(getattr(args, 'auth', [])),
            'cleanup_files': str(getattr(args, 'cleanup_files', False)),
            'storage_path': getattr(args, 'storage_path', '') or '',
        }
    
    with open(CONFIG_FILE, 'w') as f:
        config.write(f)
    console.print(f"[dim]Saved settings to {CONFIG_FILE}[/dim]" if RICH else f"Saved settings to {CONFIG_FILE}")

def apply_config_defaults(parser: argparse.ArgumentParser, config: configparser.ConfigParser) -> Tuple[argparse.ArgumentParser, Optional[str]]:
    """Apply defaults from config file to parser and return command if saved."""
    saved_cmd = None
    
    if 'DEFAULT' in config and config['DEFAULT']:
        defaults = {}
        section = config['DEFAULT']
        
        if section.get('url'):
            defaults['url'] = section['url']
        if section.get('email'):
            defaults['email'] = section['email']
        if section.get('password'):
            defaults['password'] = section['password']
        if section.get('token'):
            defaults['token'] = section['token']
        if section.get('login_collections'):
            defaults['login_collections'] = section['login_collections'].split()
        if section.get('timeout'):
            defaults['timeout'] = int(section['timeout'])
        if section.get('retries'):
            defaults['retries'] = int(section['retries'])
        if section.get('backoff'):
            defaults['backoff'] = float(section['backoff'])
        if section.get('page_size'):
            defaults['page_size'] = int(section['page_size'])
        if section.get('insecure'):
            defaults['insecure'] = section.getboolean('insecure')
        if section.get('verbose'):
            defaults['verbose'] = section.getboolean('verbose')
        
        saved_cmd = section.get('cmd')
        
        parser.set_defaults(**defaults)
    
    return parser, saved_cmd

def ask_to_use_config(has_args: bool = True) -> Tuple[bool, Optional[configparser.ConfigParser]]:
    """Ask if they want to use saved configuration but only when no args provided."""
    if not os.path.exists(CONFIG_FILE):
        return False, None
    
    config = load_config()
    if 'DEFAULT' not in config or not config['DEFAULT']:
        return False, None
    
    # Only ask if no meaningful arguments were provided
    if has_args:
        return False, None
    
    console.print("\n[cyan]Found saved configuration:[/cyan]" if RICH else "\nFound saved configuration:")
    section = config['DEFAULT']
    for key, value in section.items():
        if value:
            if key in ('password', 'token'):
                console.print(f"  {key}: (hidden)")
            else:
                console.print(f"  {key}: {value}")
    
    # Also show subcommand config if exists
    cmd = section.get('cmd')
    if cmd and cmd in config:
        console.print(f"\n[cyan]Saved {cmd} settings:[/cyan]" if RICH else f"\nSaved {cmd} settings:")
        for key, value in config[cmd].items():
            if value:
                console.print(f"  {key}: {value}")
    
    use_config = prompt_yes_no("\nUse these saved settings?")
    if not use_config:
        console.print("\nPlease provide command line arguments to run the script.")
        console.print("Use --help to see available options.")
        sys.exit(1)
    
    return use_config, config

def stream_and_delete_records(client: 'PBClient', collection: str, 
                            filter_expr: Optional[str], dry_run: bool, 
                            page_size: int = 100, batch_size: int = 50) -> Tuple[int, int]:
    """Stream records and delete in batches to avoid memory exhaustion."""
    deleted_total, errors_total = 0, 0
    page = 1
    
    while True:
        # Fetch a page of records
        params = {"perPage": min(page_size, 100), "page": page}
        if filter_expr:
            params["filter"] = filter_expr
        
        try:
            resp = client._req(
                "GET",
                f"{client.base}{RECORDS_ROUTE.format(collection)}",
                ctx=f"list {collection} page {page}",
                params=params,
            )
        except HTTPError as err:
            if err.status == 404:
                client._log(f"{collection}: vanished (404) — stopping", "yellow")
                break
            raise
        
        try:
            data = resp.json()
            items = data.get("items", [])
        except json.JSONDecodeError:
            raise PBError(f"Invalid JSON response from {collection} records: {resp.text[:200]}")
        
        if not items:
            break 
        
        # Extract IDs and delete this batch
        ids = [r["id"] for r in items]
        deleted_batch, errors_batch = purge_ids(client, collection, ids, dry_run, batch_size)
        deleted_total += deleted_batch
        errors_total += errors_batch
        
        # Check if we've reached the end
        if page >= data.get("totalPages", 1):
            break
        
        page += 1
    
    return deleted_total, errors_total

# ╔═══════════════════════════════════════════════════════════════════════
# ║  PBClient  — All network I/O with retries, back-off, SSL toggle, etc.
# ╚═══════════════════════════════════════════════════════════════════════
class PBClient:
    def __init__(
        self,
        base_url: str,
        timeout: int,
        retries: int,
        backoff: float,
        insecure: bool,
        verbose: bool,
        token: Optional[str] = None,
        logger: Optional[logging.Logger] = None,
        max_backoff: float = 60.0,  # Cap backoff
    ):
        if not re.match(r"^https?://", base_url):
            raise PBError("Base URL must start with http:// or https://")
        self.base     = base_url.rstrip("/")
        self.timeout  = timeout
        self.retries  = retries
        self.backoff  = backoff
        self.max_backoff = max_backoff
        self.verify   = False if insecure else True
        self.verbose  = verbose
        self.token    = token
        self.logger   = logger or logging.getLogger('pbnuker')
        self.sess = requests.Session()
        if self.token:
            self.sess.headers.update({"Authorization": f"Bearer {self.token}"})

    # ─── low-level request with smart retry ────────────────────────────
    def _req(self, method: str, url: str, *, ctx: str = "", **kw) -> requests.Response:
        wait = self.backoff
        for attempt in range(1, self.retries + 1):
            try:
                resp = self.sess.request(
                    method, url,
                    timeout=self.timeout,
                    verify=self.verify,
                    **kw
                )
            except requests.RequestException as exc:
                if attempt == self.retries:
                    error_msg = f"{ctx}: network error — {exc}"
                    self.logger.error(error_msg)
                    raise PBError(error_msg) from exc
                self._log(f"Network error: {exc} — retry {attempt}/{self.retries}…", "yellow")
            else:
                # HTTP response received
                if resp.ok:
                    return resp
                # 429 Back-off
                if resp.status_code == 429 and attempt < self.retries:
                    retry_after = resp.headers.get("Retry-After")
                    extra = int(retry_after) if retry_after and retry_after.isdigit() else wait
                    # Cap the backoff and add jitter
                    capped_extra = min(extra, self.max_backoff)
                    jittered_extra = capped_extra * (0.8 + 0.4 * random.random())  # ±20% jitter
                    self._log(f"429 rate-limited — sleeping {jittered_extra:.1f}s (attempt {attempt})", "yellow")
                    time.sleep(jittered_extra)
                    wait = min(wait * 2, self.max_backoff)  # Cap exponential backoff
                    continue
                # Non-retryable or out of tries
                if attempt == self.retries or resp.status_code in (401, 403, 404):
                    raise HTTPError(resp, ctx)
                self._log(f"{resp.status_code} {resp.reason} — retry {attempt}/{self.retries}…", "yellow")
            # Add random jitter to prevent surge of competing requests and cap backoff
            capped_wait = min(wait, self.max_backoff)
            jitter = capped_wait * (0.8 + 0.4 * random.random())
            time.sleep(jitter)
            wait = min(wait * 2, self.max_backoff)  # Cap exponential backoff
        assert False, "unreachable"

    def _log(self, msg: str, color: str = "cyan"):
        self.logger.info(msg)
        if self.verbose:
            console.print(f"[{color}]{msg}[/{color}]" if RICH else msg)

    # ─── public helpers ────────────────────────────────────────────────
    def login(self, email: Optional[str], pwd: Optional[str], cols: List[str]):
        if self.token:
            # Token already set in constructor - verify it works by testing API access
            try:
                self.collections() 
                console.print("✔ Using provided admin token" if RICH else "Using provided admin token")
                self.logger.info("Using provided admin token for authentication")
                return
            except (PBError, HTTPError) as e:
                # Token is invalid, clear it and fall back to email/password
                self.token = None
                self.sess.headers.pop("Authorization", None)
                self._log(f"Provided token is invalid: {e}", "yellow")
                console.print(f"[yellow]Provided token is invalid, falling back to email/password[/yellow]" if RICH 
                             else "Provided token is invalid, falling back to email/password")
        
        if not email or not pwd:
            raise PBError("Email and password are required when no token is provided")
        
        last: Exception | None = None
        for col in cols:
            try:
                resp = self._req(
                    "POST",
                    f"{self.base}{LOGIN_ROUTE.format(col)}",
                    ctx=f"login via '{col}'",
                    json={"identity": email, "password": pwd},
                )
                try:
                    data = resp.json()
                    token = data.get("token")
                except json.JSONDecodeError:
                    raise PBError(f"Invalid JSON response from login: {resp.text[:200]}")
                if not token:
                    raise PBError("No token in response")
                self.sess.headers.update({"Authorization": f"Bearer {token}"})
                console.print(f"✔ Logged in via '{col}'" if RICH else f"Logged in via {col}")
                self.logger.info(f"Successfully authenticated via collection '{col}'")
                return
            except PBError as err:
                last = err
                self._log(f"login via '{col}' failed — {err}", "yellow")
        error_msg = f"All login attempts failed. Last error: {last}"
        self.logger.error(error_msg)
        raise PBError(error_msg)

    def collections(self) -> List[dict]:
        resp = self._req("GET", self.base + API_COLLS, ctx="list collections")
        try:
            return resp.json().get("items", [])
        except json.JSONDecodeError:
            raise PBError(f"Invalid JSON response from collections endpoint: {resp.text[:200]}")



    def delete_record(self, coll: str, rid: str):
        try:
            self._req("DELETE", f"{self.base}{RECORD_ROUTE.format(coll,rid)}",
                      ctx=f"delete {coll}/{rid}")
        except HTTPError as err:
            if err.status in (404, 410):
                self._log(f"{coll}/{rid}: already gone", "yellow")
            else:
                raise

    def drop_collection(self, coll_id: str):
        self._req("DELETE", f"{self.base}{API_COLLS}/{coll_id}",
                  ctx=f"drop collection {coll_id}")

    def cleanup_files(self, storage_path: Optional[str] = None, require_confirmation: bool = False) -> int:
        """Clean up uploaded files with streaming processing. Returns number of files deleted."""
        if not storage_path:
            # Try common storage paths
            possible_paths = ["./pb_data/storage", "./storage", "../storage"]
            for path in possible_paths:
                if os.path.exists(path):
                    storage_path = path
                    break
        
        if not storage_path or not os.path.exists(storage_path):
            error_msg = f"No storage directory found to clean up. Tried: {', '.join(['./pb_data/storage', './storage', '../storage'])}"
            if require_confirmation:
                # For nuke operations, warn but don't abort the whole run
                self.logger.warning(error_msg)
                self._log(error_msg, "red")
                console.print(f"[red]Warning: {error_msg}[/red]" if RICH else f"Warning: {error_msg}")
                console.print("Continuing with collection deletion..." if RICH else "Continuing with collection deletion...")
                return 0
            else:
                self._log("No storage directory found to clean up", "yellow")
                return 0
        
        deleted_count = 0
        
        try:
            self._log(f"Processing storage directory: {storage_path}", "cyan")
            
            for root, dirs, files in os.walk(storage_path):
                for file_name in files:
                    file_path = os.path.join(root, file_name)
                    try:
                        os.remove(file_path)
                        deleted_count += 1
                        
                        # Progress reporting every 1000 files
                        if deleted_count % 1000 == 0:
                            self._log(f"Deleted {deleted_count} files so far...", "cyan")
                    except OSError as e:
                        self._log(f"Failed to delete {file_path}: {e}", "red")
                        self.logger.warning(f"Failed to delete {file_path}: {e}")
            
            if deleted_count == 0:
                self._log("No files found in storage directory", "yellow")
                return 0
            
            # Remove empty directories
            self._log("Removing empty directories...", "cyan")
            for root, dirs, files in os.walk(storage_path, topdown=False):
                for dir_name in dirs:
                    dir_path = os.path.join(root, dir_name)
                    try:
                        if not os.listdir(dir_path):  # Only remove if empty
                            os.rmdir(dir_path)
                    except OSError:
                        pass  # Directory not empty or other kind of error
            
            self.logger.info(f"Cleaned up {deleted_count} files from storage")
            return deleted_count
            
        except Exception as e:
            self._log(f"Error during file cleanup: {e}", "red")
            self.logger.error(f"File cleanup error: {e}")
            return deleted_count
    


# ╔═══════════════════════════════════════════════════════════════════════
# ║  CLI parsing
# ╚═══════════════════════════════════════════════════════════════════════
def build_parser() -> argparse.ArgumentParser:
    P = argparse.ArgumentParser(
        prog="pbnuker.py",
        description="Delete PocketBase records or collections safely.",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    # Globals
    P.add_argument("-u", "--url", default="http://localhost:8090", 
                   help="PB base URL")
    P.add_argument("-e", "--email", help="Login email (required unless --token provided)")
    P.add_argument("-p", "--password", help="Login password (required unless --token provided)")
    P.add_argument("-t", "--token", help="Admin API token (alternative to email/password)")
    P.add_argument("--clear-config", action="store_true", 
                   help="Delete saved configuration file (can be combined with other commands)")
    P.add_argument("--login-collections", nargs="+",
                   default=["users", "_superusers", "_admins"],
                   help="Auth collections to try (in order)")
    P.add_argument("--timeout", type=int, default=15, help="HTTP timeout (s)")
    P.add_argument("--retries", type=int, default=3, help="Max HTTP retries")
    P.add_argument("--backoff", type=float, default=0.6, help="Initial retry backoff delay (s)")
    P.add_argument("--page-size", type=int, default=100, help="Records per page (capped at 100)")
    P.add_argument("--insecure", action="store_true", help="Skip TLS cert verify")
    P.add_argument("--verbose", action="store_true", help="Extra progress lines")
    P.add_argument("--dry-run", action="store_true", help="Only show what would happen")
    P.add_argument("-y", "--yes", action="store_true", help="Skip confirmation prompt")
    P.add_argument("--log-file", help="Log file path")

    sub = P.add_subparsers(dest="cmd", required=True)

    pc = sub.add_parser("purge-collection", help="Delete records in one collection")
    pc.add_argument("collection", help="Collection name")
    pc.add_argument("-f", "--filter", help="PocketBase filter expression")
    pc.add_argument("--before", metavar="YYYY-MM-DD[THH:MM:SS[Z]]",
                    help="Delete records created before this timestamp (UTC if Z suffix)")
    pc.add_argument("--ids", nargs="+", help="Explicit record IDs to delete")

    sub.add_parser("purge-all", help="Empty every non-system collection")

    nu = sub.add_parser("nuke", help="Drop every collection except auth ones")
    nu.add_argument("--auth", nargs="+", default=["users", "_superusers", "_admins"],
                    help="Collections to keep")
    nu.add_argument("--cleanup-files", action="store_true",
                    help="Also delete uploaded files from storage")
    nu.add_argument("--storage-path", help="Custom storage directory path")

    return P

# ╔═══════════════════════════════════════════════════════════════════════
# ║  Helpers
# ╚═══════════════════════════════════════════════════════════════════════
def validate_filter_syntax(filter_expr: str) -> str:
    """Basic validation of filter expression syntax."""
    if not filter_expr:
        return filter_expr
    
    # Check for balanced parentheses
    paren_count = 0
    for char in filter_expr:
        if char == '(':
            paren_count += 1
        elif char == ')':
            paren_count -= 1
        if paren_count < 0:
            raise FilterParseError(f"Unbalanced parentheses in filter: {filter_expr}")
    
    if paren_count != 0:
        raise FilterParseError(f"Unbalanced parentheses in filter: {filter_expr}")
    
    # Check for balanced quotes (basic check)
    single_quotes = filter_expr.count("'")
    double_quotes = filter_expr.count('"')
    
    if single_quotes % 2 != 0:
        raise FilterParseError(f"Unbalanced single quotes in filter: {filter_expr}")
    if double_quotes % 2 != 0:
        raise FilterParseError(f"Unbalanced double quotes in filter: {filter_expr}")
    
    return filter_expr

def compile_filter(filt: Optional[str], before: Optional[str]) -> Optional[str]:
    out = filt or ""
    
    # Validate user filter syntax
    if out:
        out = validate_filter_syntax(out)
    
    if before:
        try:
            # Parse the timestamp more robustly with multiple fallback strategies
            parsed_dt = None
            original_before = before.strip()
            
            # Strategy 1: Try ISO format variations
            if 'T' in original_before:
                # Full datetime - handle various timezone formats
                if original_before.endswith('Z'):
                    # UTC with Z suffix
                    parsed_dt = dt.datetime.fromisoformat(original_before[:-1]).replace(tzinfo=dt.timezone.utc)
                elif original_before.endswith('+00:00') or original_before.endswith('-00:00'):
                    # UTC with explicit offset
                    parsed_dt = dt.datetime.fromisoformat(original_before).astimezone(dt.timezone.utc)
                elif '+' in original_before[-6:] or (original_before.count('-') > 2 and ':' in original_before[-6:]):
                    # Has timezone offset
                    parsed_dt = dt.datetime.fromisoformat(original_before).astimezone(dt.timezone.utc)
                else:
                    # No timezone, assume UTC
                    parsed_dt = dt.datetime.fromisoformat(original_before).replace(tzinfo=dt.timezone.utc)
            else:
                # Strategy 2: Date only formats
                if len(original_before) == 10 and original_before.count('-') == 2:
                    # YYYY-MM-DD format
                    date_part = dt.datetime.fromisoformat(original_before).date()
                    parsed_dt = dt.datetime.combine(date_part, dt.time(23, 59, 59), dt.timezone.utc)
                elif len(original_before) == 8 and original_before.isdigit():
                    # YYYYMMDD format
                    year = int(original_before[:4])
                    month = int(original_before[4:6])
                    day = int(original_before[6:8])
                    date_part = dt.date(year, month, day)
                    parsed_dt = dt.datetime.combine(date_part, dt.time(23, 59, 59), dt.timezone.utc)
                else:
                    # Try parsing as date anyway
                    date_part = dt.datetime.fromisoformat(original_before).date()
                    parsed_dt = dt.datetime.combine(date_part, dt.time(23, 59, 59), dt.timezone.utc)
            
            if parsed_dt is None:
                raise ValueError("Could not parse timestamp")
            
            # Convert back to ISO string with Z suffix for PocketBase
            timestamp = parsed_dt.strftime('%Y-%m-%dT%H:%M:%SZ')
            
        except (ValueError, TypeError, OverflowError) as e:
            # Provide helpful error message with examples
            error_msg = f"Invalid --before timestamp '{original_before}': {str(e)}"
            error_msg += "\nSupported formats:"
            error_msg += "\n  • YYYY-MM-DD (e.g., 2023-12-25)"
            error_msg += "\n  • YYYY-MM-DDTHH:MM:SS (e.g., 2023-12-25T10:30:00)"
            error_msg += "\n  • YYYY-MM-DDTHH:MM:SSZ (e.g., 2023-12-25T10:30:00Z)"
            error_msg += "\n  • YYYY-MM-DDTHH:MM:SS±HH:MM (e.g., 2023-12-25T10:30:00+02:00)"
            error_msg += "\n  • YYYYMMDD (e.g., 20231225)"
            raise FilterParseError(error_msg)
        
        crit = f'created<"{timestamp}"'
        out = crit if not out else f"({out}) && ({crit})"
    return out or None

def purge_ids(client: PBClient, coll: str, ids: List[str], dry: bool, batch_size: int = 50) -> Tuple[int,int]:
    """Delete records in synchronous batches with progress tracking."""
    if not ids:
        console.print(f"[dim]{coll}: no matches[/dim]" if RICH else f"{coll}: 0")
        return 0,0
    
    action = "Would delete" if dry else "Deleting"
    console.print(f"{action} {len(ids)} from [bold]{coll}[/bold]" if RICH
                  else f"{coll}: {action.lower()} {len(ids)}")
    
    if dry:
        # In dry-run, show some sample IDs but don't overwhelm
        sample_ids = ids[:10]
        for rid in sample_ids:
            console.print(f"[yellow]- {rid}[/yellow]" if RICH else f"- {rid}")
        if len(ids) > 10:
            console.print(f"[yellow]... and {len(ids) - 10} more[/yellow]" if RICH 
                         else f"... and {len(ids) - 10} more")
        return len(ids), 0  # "would delete", no errors
    
    deleted, errors = 0, 0
    
    # Process in batches 
    for i in range(0, len(ids), batch_size):
        batch = ids[i:i + batch_size]
        batch_deleted, batch_errors = 0, 0
        
        for rid in batch:
            try:
                client.delete_record(coll, rid)
                batch_deleted += 1
            except PBError as e:
                client._log(str(e), "red")
                batch_errors += 1
        
        deleted += batch_deleted
        errors += batch_errors
        
        progress = min(i + batch_size, len(ids))
        client._log(f"{coll}: {progress}/{len(ids)} processed ({deleted} ok, {errors} failed)", "cyan")
    
    color = "green" if errors == 0 else "red"
    console.print(f"[{color}]✓ {coll}: {deleted} ok, {errors} failed[/{color}]"
                  if RICH else f"{coll}: ok={deleted}, failed={errors}")
    return deleted, errors

def graceful_exit(sig, frame):  # noqa
    """Handle SIGINT and SIGTERM gracefully."""
    signal_name = "SIGINT" if sig == signal.SIGINT else "SIGTERM"
    console.print(f"\n[red]Received {signal_name} — aborting[/red]" if RICH else f"\nReceived {signal_name} — aborting")
    sys.exit(130)

def ignore_sigpipe(sig, frame):  # noqa
    """Ignore SIGPIPE to handle broken pipes gracefully."""
    pass

# ╔═══════════════════════════════════════════════════════════════════════
# ║  Main
# ╚═══════════════════════════════════════════════════════════════════════
def has_meaningful_args(argv: Optional[List[str]] = None) -> bool:
    """Check if meaningful arguments were provided that would define a complete run."""
    if not argv:
        argv = sys.argv[1:]
    
    # Filter out help and info-only flags first
    info_only_flags = ['--help', '-h', '--clear-config']
    filtered_args = [arg for arg in argv if arg not in info_only_flags]
    
    if not filtered_args:
        return False
    
    subcommands = ['purge-collection', 'purge-all', 'nuke']
    if any(arg in subcommands for arg in filtered_args):
        return True
    
    meaningful_flags = [arg for arg in filtered_args if arg.startswith('-')]
    
    return len(meaningful_flags) > 0

def main(argv: Optional[List[str]] = None):
    # Set up signal handlers for clean shutdown
    signal.signal(signal.SIGINT, graceful_exit)
    signal.signal(signal.SIGTERM, graceful_exit)
    # Ignore SIGPIPE to handle broken pipes gracefully like head
    if platform.system() != "Windows" and hasattr(signal, 'SIGPIPE'):
        signal.signal(signal.SIGPIPE, ignore_sigpipe)
    
    if argv is None:
        argv = sys.argv[1:]
    
    # Special handling for --clear-config as it can work without subcommands
    if '--clear-config' in argv and len([arg for arg in argv if not arg.startswith('-')]) == 0:
        # Only --clear-config and flags, no subcommand
        if os.path.exists(CONFIG_FILE):
            os.remove(CONFIG_FILE)
            console.print(f"[green]Deleted configuration file: {CONFIG_FILE}[/green]" if RICH 
                         else f"Deleted configuration file: {CONFIG_FILE}")
        else:
            console.print(f"[yellow]No configuration file found: {CONFIG_FILE}[/yellow]" if RICH 
                         else f"No configuration file found: {CONFIG_FILE}")
        sys.exit(0)
    
    parser = build_parser()
    
    # Check if we have meaningful arguments
    has_args = has_meaningful_args(argv)
    
    # Check for saved config and ask user only if no meaningful args provided
    use_saved_config, config = ask_to_use_config(has_args)
    saved_cmd = None
    if use_saved_config and config:
        parser, saved_cmd = apply_config_defaults(parser, config)
    
    # If we have a saved command, inject it into argv for parsing
    if saved_cmd and not has_args:
        if argv is None:
            argv = []
        argv = [saved_cmd] + argv

    args = parser.parse_args(argv)
    
    # Handle config clearing after parsing (for compound commands)
    if hasattr(args, 'clear_config') and args.clear_config:
        if os.path.exists(CONFIG_FILE):
            os.remove(CONFIG_FILE)
            console.print(f"[green]Deleted configuration file: {CONFIG_FILE}[/green]" if RICH 
                         else f"Deleted configuration file: {CONFIG_FILE}")
        else:
            console.print(f"[yellow]No configuration file found: {CONFIG_FILE}[/yellow]" if RICH 
                         else f"No configuration file found: {CONFIG_FILE}")
        # Continue with the rest of the command
    
    # Apply subcommand-specific config if available
    if use_saved_config and config and hasattr(args, 'cmd') and args.cmd in config:
        cmd_config = config[args.cmd]
        
        if args.cmd == 'purge-collection':
            if not hasattr(args, 'collection') or not args.collection:
                if cmd_config.get('collection'):
                    args.collection = cmd_config['collection']
            if not hasattr(args, 'filter') or not args.filter:
                if cmd_config.get('filter'):
                    args.filter = cmd_config['filter']
            if not hasattr(args, 'before') or not args.before:
                if cmd_config.get('before'):
                    args.before = cmd_config['before']
        
        elif args.cmd == 'purge-all':
            pass
        
        elif args.cmd == 'nuke':
            if not hasattr(args, 'auth') or not args.auth:
                if cmd_config.get('auth'):
                    args.auth = cmd_config['auth'].split()
            if not hasattr(args, 'cleanup_files') or not args.cleanup_files:
                if cmd_config.get('cleanup_files'):
                    args.cleanup_files = cmd_config.getboolean('cleanup_files')
            if not hasattr(args, 'storage_path') or not args.storage_path:
                if cmd_config.get('storage_path'):
                    args.storage_path = cmd_config['storage_path']
    
    # Prompt for missing credentials if needed
    if not args.token and not args.email:
        if sys.stdin.isatty():
            args.email = input("Email: ").strip()
        else:
            die("Email is required when no token is provided", 1)
    
    if not args.token and not args.password:
        if sys.stdin.isatty():
            import getpass
            args.password = getpass.getpass("Password: ")
        else:
            die("Password is required when no token is provided", 1)
    
    # Validate authentication requirements
    if not args.token and (not args.email or not args.password):
        die("Either --token or both --email and --password are required", 1)

    # Setup logging func
    if not args.log_file:
        timestamp = dt.datetime.now().strftime("%Y%m%d_%H%M%S")
        args.log_file = f"pbnuker_{timestamp}.log"
    
    logger = setup_logging(args.log_file, args.verbose)
    logger.info(f"PBNuker started with command: {args.cmd}")
    console.print(f"[dim]Logging to: {args.log_file}[/dim]" if RICH else f"Logging to: {args.log_file}")

    # Mutually exclusive flags
    if args.cmd=="purge-collection" and args.ids and (args.filter or args.before):
        die("--ids cannot be combined with --filter/--before")

    # Confirm for all destructive operations (skip for dry-run)
    if not args.dry_run and not (args.yes or prompt_yes_no("This is irreversible — continue?", args.yes)):
        console.print("Aborted."); return

    t0 = time.perf_counter()
    deleted_total=failed_total=dropped_total=would_drop_total=skipped_coll=net_err=files_deleted=0

    try:
        client = PBClient(
            args.url, args.timeout, args.retries, args.backoff,
            args.insecure, args.verbose, args.token, logger
        )
        client.login(args.email, args.password, args.login_collections)

        if args.cmd=="purge-collection":
            colls = {c["name"]:c for c in client.collections()}
            if args.collection not in colls:
                die(f"Collection '{args.collection}' not found")
            
            try:
                filter_expr = compile_filter(args.filter, args.before)
            except FilterParseError as e:
                die(str(e), 1)
            
            if args.ids:
                deleted, errors = purge_ids(client, args.collection, args.ids, args.dry_run)
            else:
                deleted, errors = stream_and_delete_records(
                    client, args.collection, filter_expr, 
                    args.dry_run, args.page_size
                )
            deleted_total += deleted
            failed_total += errors

        elif args.cmd=="purge-all":
            for c in client.collections():
                if c["system"]: continue
                try:
                    deleted, errors = stream_and_delete_records(
                        client, c["name"], None, args.dry_run, args.page_size
                    )
                    deleted_total += deleted
                    failed_total += errors
                except PBError:
                    skipped_coll += 1
                    continue

        elif args.cmd=="nuke":
            for c in client.collections():
                if c.get("system", False) or c["name"] in args.auth:
                    console.print(f"• keep '{c['name']}'"); continue
                
                action = "Would drop" if args.dry_run else "Dropping"
                console.print(f"{action} [bold]{c['name']}[/bold]" if RICH
                              else f"{action} {c['name']}")
                
                if args.dry_run:
                    would_drop_total += 1
                else:
                    try:
                        client.drop_collection(c["id"])
                        dropped_total += 1
                    except PBError:
                        net_err += 1
                        continue
            
            # Handle file cleanup
            if hasattr(args, 'cleanup_files') and args.cleanup_files:
                if args.dry_run:
                    console.print("[yellow]Would clean up uploaded files[/yellow]" if RICH
                                 else "Would clean up uploaded files")
                else:
                    storage_path = getattr(args, 'storage_path', None)
                    files_deleted = client.cleanup_files(storage_path, require_confirmation=True)

    except PBError as exc:
        logger.error(f"PBError: {exc}")
        die(str(exc), 2)

    # Save configuration for future runs (only on successful completion)
    if not args.dry_run:  # Only save config if it was a real run
        save_config(args)
    
    # ─── summary ────────────────────────────────────────────────────────
    elapsed=time.perf_counter()-t0
    logger.info(f"Operation completed in {elapsed:.2f}s")
    
    if RICH:
        tab=Table(title="Summary", show_lines=True)
        for col in ("Metric","Value"): tab.add_column(col, style="cyan")
        
        if args.dry_run:
            tab.add_row("Records would delete", str(deleted_total))
            tab.add_row("Collections would drop", str(would_drop_total))
        else:
            tab.add_row("Records deleted", str(deleted_total))
            tab.add_row("Collections dropped", str(dropped_total))
        
        tab.add_row("Record errors", str(failed_total))
        tab.add_row("Skipped collections", str(skipped_coll))
        tab.add_row("Network/API errors", str(net_err))
        if files_deleted > 0:
            tab.add_row("Files deleted", str(files_deleted))
        tab.add_row("Dry-run", "yes" if args.dry_run else "no")
        tab.add_row("Elapsed (s)", f"{elapsed:.2f}")
        tab.add_row("Log file", args.log_file)
        console.rule(); console.print(tab)
    else:
        summary_parts = [
            f"del={deleted_total}",
            f"err={failed_total}",
            f"skipped={skipped_coll}",
            f"api_err={net_err}",
            f"dry={args.dry_run}",
            f"time={elapsed:.2f}s"
        ]
        
        if args.dry_run:
            summary_parts.insert(1, f"would_drop={would_drop_total}")
        else:
            summary_parts.insert(1, f"dropped={dropped_total}")
        
        if files_deleted > 0:
            summary_parts.insert(-2, f"files_del={files_deleted}")
        
        console.print(f"\nSUMMARY  {' '.join(summary_parts)}")
        console.print(f"Log: {args.log_file}")

# ─── exit codes for CI scripts ──────────────────────────────────────────
# 0  OK
# 1  user / validation error (die())
# 2  PocketBase / network error (PBError caught)
# 130 SIGINT
# 99 unhandled (should not happen)
# ────────────────────────────────────────────────────────────────────────
class UnexpectedError(Exception):
    """Wrapper for unexpected errors to make script embeddable."""
    def __init__(self, original_exc: Exception, traceback_str: str):
        self.original_exc = original_exc
        self.traceback_str = traceback_str
        super().__init__(f"Unexpected error: {original_exc}")

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        # Handle Ctrl-C not caught by signal handler
        console.print("\n[red]Interrupted[/red]" if RICH else "\nInterrupted")
        sys.exit(130)
    except (PBError, requests.RequestException, FilterParseError) as exc:
        # Network/API/filter errors
        die(f"Error: {exc}", 2 if isinstance(exc, (PBError, requests.RequestException)) else 1)
    except (OSError, IOError) as exc:
        # File system errors
        die(f"File system error: {exc}", 1)
    except Exception as exc:
        # Truly unexpected errors - handle differently when embedded vs standalone
        import traceback
        tb_str = traceback.format_exc()
        
        # When run as script show error and exit
        if __name__ == "__main__":
            console.print(f"[red]Unexpected error: {exc}[/red]" if RICH else f"Unexpected error: {exc}")
            console.print(f"[dim]{tb_str}[/dim]" if RICH else tb_str)
            sys.exit(99)
        else:
            # When imported/embedded raise without side effects
            raise UnexpectedError(exc, tb_str)
