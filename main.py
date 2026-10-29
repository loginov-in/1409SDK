"""1409 SDK — Flask Dev Server + Admin Panel."""

from __future__ import annotations

import hmac
import os
import secrets
import time
from functools import wraps
from pathlib import Path

from flask import (
    Flask,
    abort,
    jsonify,
    redirect,
    render_template,
    request,
    session,
    url_for,
)

BASE_DIR = Path(__file__).resolve().parent
STATIC_DIR = BASE_DIR / "static"
TEMPLATES_DIR = BASE_DIR / "templates"
COMPONENTS_DIR = TEMPLATES_DIR / "components"


def _load_dotenv(path: Path) -> None:
    """Minimal .env loader (no external dependencies)."""
    if not path.is_file():
        return
    for raw in path.read_text(encoding="utf-8").splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        if line.startswith("export "):
            line = line[len("export "):]
        if "=" not in line:
            continue
        key, value = line.split("=", 1)
        key = key.strip()
        value = value.strip().strip("\"'")
        if key and key not in os.environ:
            os.environ[key] = value


_load_dotenv(BASE_DIR / ".env")

app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY", "1409-sdk-dev-secret-change-me")
app.config.update(
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
    PERMANENT_SESSION_LIFETIME=60 * 60 * 24 * 7,
)

ADMIN_LOGIN = os.environ.get("ADMIN_LOGIN", "admin")
ADMIN_PASSWORD = os.environ.get("ADMIN_PASSWORD", "1409")

MAX_ATTEMPTS = 5
ATTEMPT_WINDOW = 300
_attempts: dict[str, list[float]] = {}

FILE_EXTENSIONS = {".css", ".html", ".js"}
MAX_FILE_BYTES = 512 * 1024


# ─── HELPERS ───────────────────────────────────────────
def _rel(path: Path) -> str:
    return path.relative_to(BASE_DIR).as_posix()


def _collect_files() -> tuple[list[str], list[str], list[str]]:
    css_dir = STATIC_DIR / "css"
    css_files = sorted(_rel(p) for p in css_dir.rglob("*.css")) if css_dir.is_dir() else []

    html_files = (
        sorted(_rel(p) for p in COMPONENTS_DIR.rglob("*.html"))
        if COMPONENTS_DIR.is_dir()
        else []
    )

    static_files = []
    if STATIC_DIR.is_dir():
        for p in STATIC_DIR.rglob("*"):
            if not p.is_file():
                continue
            rel = p.relative_to(STATIC_DIR)
            if rel.parts and rel.parts[0] == "css":
                continue
            static_files.append(_rel(p))
    static_files.sort()

    return css_files, html_files, static_files


def _csrf_token() -> str:
    token = session.get("csrf_token")
    if not token:
        token = secrets.token_urlsafe(32)
        session["csrf_token"] = token
    return token


def _safe_next(target: str | None) -> str | None:
    if not target:
        return None
    if not target.startswith("/") or target.startswith("//"):
        return None
    return target


def _client_ip() -> str:
    forwarded = request.headers.get("X-Forwarded-For", "")
    return forwarded.split(",")[0].strip() or request.remote_addr or "unknown"


def _attempts_left(ip: str) -> int:
    now = time.time()
    hits = [t for t in _attempts.get(ip, []) if now - t < ATTEMPT_WINDOW]
    _attempts[ip] = hits
    return MAX_ATTEMPTS - len(hits)


def _register_failure(ip: str) -> None:
    _attempts.setdefault(ip, []).append(time.time())


def login_required(view):
    @wraps(view)
    def wrapped(*args, **kwargs):
        if not session.get("user"):
            return redirect(url_for("login", next=request.full_path.rstrip("?")))
        return view(*args, **kwargs)

    return wrapped


# ─── AUTH ──────────────────────────────────────────────
@app.route("/")
def index():
    if session.get("user"):
        return redirect(url_for("panel"))
    return redirect(url_for("login"))


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "GET":
        if session.get("user"):
            return redirect(url_for("panel"))
        return render_template(
            "login.html",
            csrf_token=_csrf_token(),
            error=None,
            login_value="",
            next=_safe_next(request.args.get("next")) or "",
        )

    ip = _client_ip()
    if _attempts_left(ip) <= 0:
        return (
            render_template(
                "login.html",
                csrf_token=_csrf_token(),
                error="Слишком много попыток входа. Подождите несколько минут.",
                login_value=request.form.get("login", ""),
                next=_safe_next(request.form.get("next")) or "",
            ),
            429,
        )

    sent_token = request.form.get("csrf_token", "")
    if not hmac.compare_digest(sent_token, session.get("csrf_token", "")):
        abort(400)

    login_value = request.form.get("login", "").strip()
    password = request.form.get("password", "")

    login_ok = hmac.compare_digest(login_value, ADMIN_LOGIN)
    password_ok = hmac.compare_digest(password, ADMIN_PASSWORD)

    if not (login_ok and password_ok):
        _register_failure(ip)
        return (
            render_template(
                "login.html",
                csrf_token=_csrf_token(),
                error="Неверный логин или пароль.",
                login_value=login_value,
                next=_safe_next(request.form.get("next")) or "",
            ),
            401,
        )

    _attempts.pop(ip, None)
    remember = request.form.get("remember") == "on"

    session.clear()
    session["user"] = ADMIN_LOGIN
    session["csrf_token"] = secrets.token_urlsafe(32)
    session.permanent = remember

    return redirect(_safe_next(request.form.get("next")) or url_for("panel"))


@app.route("/logout", methods=["GET", "POST"])
def logout():
    session.clear()
    return redirect(url_for("login"))


# ─── PANEL ─────────────────────────────────────────────
@app.route("/panel")
@login_required
def panel():
    css_files, html_files, static_files = _collect_files()
    return render_template(
        "panel.html",
        css_files=css_files,
        html_files=html_files,
        static_files=static_files,
        user=session.get("user"),
    )


# ─── API ───────────────────────────────────────────────
@app.route("/api/file-content")
@login_required
def file_content():
    raw = request.args.get("path", "")
    if not raw:
        abort(400)

    candidate = (BASE_DIR / raw).resolve()
    allowed_roots = (STATIC_DIR.resolve(), TEMPLATES_DIR.resolve())
    if not any(candidate.is_relative_to(root) for root in allowed_roots):
        abort(403)
    if candidate.suffix.lower() not in FILE_EXTENSIONS or not candidate.is_file():
        abort(404)
    if candidate.stat().st_size > MAX_FILE_BYTES:
        abort(413)

    return jsonify(
        path=_rel(candidate),
        content=candidate.read_text(encoding="utf-8", errors="replace"),
    )


PICKER_SCRIPT = """
<script>
(function () {
  if (window.__sdkPicker) return;
  window.__sdkPicker = true;

  var active = false, overlay = null, current = null;

  function ensureOverlay() {
    if (overlay) return overlay;
    overlay = document.createElement('div');
    overlay.style.cssText = 'position:fixed;pointer-events:none;z-index:2147483646;border:1px solid #6366f1;background:rgba(99,102,241,0.12);border-radius:4px;display:none;transition:all .05s';
    document.body.appendChild(overlay);
    return overlay;
  }

  function selector(el) {
    if (el.id) return '#' + CSS.escape(el.id);
    var parts = [];
    while (el && el.nodeType === 1 && el !== document.body && el !== document.documentElement) {
      var part = el.tagName.toLowerCase();
      if (el.classList.length) {
        part += '.' + Array.prototype.map.call(el.classList, function (c) { return CSS.escape(c); }).join('.');
      }
      var parent = el.parentElement;
      if (parent) {
        var same = Array.prototype.filter.call(parent.children, function (c) { return c.tagName === el.tagName; });
        if (same.length > 1) part += ':nth-of-type(' + (same.indexOf(el) + 1) + ')';
      }
      parts.unshift(part);
      if (el.id) { parts[0] = '#' + CSS.escape(el.id); break; }
      el = parent;
    }
    return parts.join(' > ');
  }

  function collectCss(el) {
    var out = [];
    try {
      for (var i = 0; i < document.styleSheets.length; i++) {
        var sheet = document.styleSheets[i];
        var rules;
        try { rules = sheet.cssRules; } catch (e) { continue; }
        if (!rules) continue;
        for (var j = 0; j < rules.length; j++) {
          var rule = rules[j];
          if (rule.selectorText) {
            try { if (el.matches(rule.selectorText)) out.push(rule.cssText); } catch (e) {}
          } else if (rule.cssRules) {
            for (var k = 0; k < rule.cssRules.length; k++) {
              var inner = rule.cssRules[k];
              if (inner.selectorText) {
                try { if (el.matches(inner.selectorText)) out.push(inner.cssText); } catch (e) {}
              }
            }
          }
        }
      }
    } catch (e) {}

    var cs = getComputedStyle(el);
    var computed = [
      'display: ' + cs.display,
      'position: ' + cs.position,
      'color: ' + cs.color,
      'background: ' + cs.background,
      'font-size: ' + cs.fontSize,
      'font-weight: ' + cs.fontWeight,
      'padding: ' + cs.padding,
      'margin: ' + cs.margin,
      'border: ' + cs.border,
      'border-radius: ' + cs.borderRadius
    ].join(';\\n  ');

    return '/* ' + selector(el) + ' */\\n{\\n  ' + computed + ';\\n}\\n\\n/* matched rules */\\n' + out.join('\\n');
  }

  function cleanup() {
    active = false;
    document.body.style.cursor = '';
    if (overlay) overlay.style.display = 'none';
    current = null;
  }

  document.addEventListener('mousemove', function (e) {
    if (!active) return;
    var el = e.target;
    if (!el || el === overlay || el === document.documentElement) return;
    current = el;
    var o = ensureOverlay();
    var r = el.getBoundingClientRect();
    o.style.display = 'block';
    o.style.left = r.left + 'px';
    o.style.top = r.top + 'px';
    o.style.width = r.width + 'px';
    o.style.height = r.height + 'px';
  }, true);

  document.addEventListener('click', function (e) {
    if (!active) return;
    e.preventDefault();
    e.stopPropagation();
    var el = e.target;
    if (!el) return;
    var data = {
      type: 'pickedElement',
      tag: el.tagName.toLowerCase(),
      path: selector(el),
      html: el.outerHTML,
      css: collectCss(el)
    };
    cleanup();
    if (window.parent !== window) window.parent.postMessage(data, '*');
  }, true);

  window.addEventListener('message', function (e) {
    if (e.data && e.data.type === 'enablePicker') {
      active = true;
      document.body.style.cursor = 'crosshair';
      ensureOverlay();
    } else if (e.data && e.data.type === 'disablePicker') {
      cleanup();
    }
  });
})();
</script>
"""


@app.route("/preview/<path:name>")
@login_required
def preview(name: str):
    if Path(name).name != name or not name.lower().endswith(".html"):
        abort(404)

    target = COMPONENTS_DIR / name
    if not target.is_file():
        abort(404)

    try:
        html = render_template(f"components/{name}")
    except Exception:
        html = target.read_text(encoding="utf-8", errors="replace")

    if "</body>" in html:
        html = html.replace("</body>", PICKER_SCRIPT + "</body>")
    else:
        html += PICKER_SCRIPT

    return html


if __name__ == "__main__":
    if app.secret_key == "1409-sdk-dev-secret-change-me":
        print("⚠  SECRET_KEY не задан — используется dev-ключ.")
    print("1409 SDK Admin Server → http://localhost:9350")
    if ADMIN_LOGIN == "admin" and ADMIN_PASSWORD == "1409":
        print("   Dev-доступ: admin / 1409 (переопределяется ADMIN_LOGIN и ADMIN_PASSWORD)")
    app.run(debug=True, port=9350)
