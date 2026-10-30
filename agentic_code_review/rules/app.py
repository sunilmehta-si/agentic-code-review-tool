"""Application-code security rules for Python and JavaScript/TypeScript, and a few for Go.

These are intentionally narrow, high-precision patterns. Broad SAST coverage comes from
Semgrep/CodeQL when installed; these keep the review useful when they are not.
"""
from __future__ import annotations

import io
import re
import tokenize

from ..models import Severity
from .base import ignored, line_matches, make, rule

PY = ["lang:python"]
JS = ["lang:javascript", "lang:typescript"]
GO = ["lang:go"]


@rule("ACR-APP-001", "SQL built with string formatting", Severity.HIGH, "app-security", PY + JS + GO,
      fix="Use parameterised queries (placeholders + a parameters tuple, or $1/? args in Go), never f-strings, %, +, "
          ".format or fmt.Sprintf to build SQL.",
      references=["https://owasp.org/Top10/A03_2021-Injection/"])
def sql_formatting(path, text, lines):
    pat = re.compile(r"""\.(execute|executemany|raw|query)\(\s*(f["']|["'][^"']*["']\s*(%|\+|\.format\())""", re.I)
    sql_js = re.compile(r"""\.query\(\s*`[^`]*\$\{""")
    # database/sql, sqlx, pgx and GORM: the statement is the first argument; fmt.Sprintf or + on it is the bug
    # (not Get or Select: sqlx's take the destination first, and http.Client.Get takes a URL, which is often built)
    sql_go = re.compile(r"""\.(Query|QueryRow|Exec|Prepare|Raw|Where)(Context)?\(\s*(ctx,\s*)?(fmt\.Sprintf\(|"[^"]*"\s*\+)""")
    yield from line_matches(sql_formatting.info, path, lines, pat)
    yield from line_matches(sql_formatting.info, path, lines, sql_js)
    yield from line_matches(sql_formatting.info, path, lines, sql_go)


@rule("ACR-APP-002", "Shell command built from a string", Severity.HIGH, "app-security", PY + JS + GO,
      fix="Pass an argument list without a shell (subprocess.run([...]) / execFile / exec.Command(name, args...)), "
          "and validate any user input.",
      references=["https://cwe.mitre.org/data/definitions/78.html"])
def shell_injection(path, text, lines):
    py = re.compile(r"\b(subprocess\.(run|call|Popen|check_output|check_call)\(.*shell\s*=\s*True|os\.system\(|os\.popen\()")
    js = re.compile(r"""\b(child_process\.)?exec(Sync)?\(\s*(`[^`]*\$\{|[^)]*\+)""")  # acr:ignore - rule pattern, not a call
    # a shell asked to parse a command that is not one literal closing the call: the third argument starts with
    # something other than a quote (a variable, a Sprintf), or is a literal followed by a + rather than the )
    go = re.compile(r"""\bexec\.Command(Context)?\(\s*(ctx,\s*)?"(/bin/)?(sh|bash|zsh|dash|cmd|powershell)(\.exe)?",\s*"(-c|/[cC])",\s*"""
                    r"""(?:[^\s"]|"[^"]*"\s*[^\s)])""")
    yield from line_matches(shell_injection.info, path, lines, py)
    yield from line_matches(shell_injection.info, path, lines, js)
    yield from line_matches(shell_injection.info, path, lines, go)


@rule("ACR-APP-003", "Dynamic code execution", Severity.HIGH, "app-security", PY + JS,
      fix="Remove eval/exec/new Function. Parse data with a real parser (json.loads, ast.literal_eval) instead.")
def dynamic_exec(path, text, lines):
    pat = re.compile(r"(?<![\w.])(eval|exec)\(|\bnew Function\(")
    yield from line_matches(dynamic_exec.info, path, lines, pat)


@rule("ACR-APP-004", "Unsafe deserialisation", Severity.HIGH, "app-security", PY,
      fix="Use yaml.safe_load / json; never unpickle data that can come from outside the process. For models, prefer "
          "safetensors or ONNX over pickle-based joblib/.pkl files.",
      references=["https://cwe.mitre.org/data/definitions/502.html"])
def unsafe_deserialise(path, text, lines):
    pat = re.compile(r"\b(pickle|cPickle|dill|shelve)\.(loads?|Unpickler)\(|\byaml\.load\((?![^)]*SafeLoader)|\byaml\.unsafe_load\("
                     # joblib, pandas and numpy pickles run arbitrary code on load as well
                     r"|\bjoblib\.load\(|\b(pd|pandas)\.read_pickle\(|\b(np|numpy)\.load\([^)]*allow_pickle\s*=\s*True")
    yield from line_matches(unsafe_deserialise.info, path, lines, pat)


@rule("ACR-APP-005", "TLS certificate verification disabled", Severity.MEDIUM, "app-security", PY + JS + GO,
      fix="Keep verification on. If a private CA is needed, point the client at that CA bundle (RootCAs in Go) instead.")
def tls_off(path, text, lines):
    pat = re.compile(r"verify\s*=\s*False|rejectUnauthorized\s*:\s*false|NODE_TLS_REJECT_UNAUTHORIZED\s*=\s*['\"]?0|ssl\._create_unverified_context"
                     r"|InsecureSkipVerify:\s*true\b|\.InsecureSkipVerify\s*=\s*true\b|grpc\.WithInsecure\(\)")
    yield from line_matches(tls_off.info, path, lines, pat)


@rule("ACR-APP-006", "Debug mode enabled in application code", Severity.MEDIUM, "app-security", PY,
      fix="Drive debug from configuration that is off by default; never ship debug=True.")
def debug_on(path, text, lines):
    pat = re.compile(r"\.run\([^)]*debug\s*=\s*True|^\s*DEBUG\s*=\s*True\b")
    yield from line_matches(debug_on.info, path, lines, pat)


@rule("ACR-APP-007", "Weak hash used for security", Severity.LOW, "app-security", PY + JS,
      fix="Use SHA-256+ for integrity, and bcrypt/scrypt/argon2 for passwords.")
def weak_hash(path, text, lines):
    pat = re.compile(r"hashlib\.(md5|sha1)\(|createHash\(\s*['\"](md5|sha1)['\"]")
    yield from line_matches(weak_hash.info, path, lines, pat)


@rule("ACR-APP-008", "JWT accepted without verifying its signature or expiry", Severity.CRITICAL, "app-security", PY + JS,
      fix="Always verify: pass the key and an explicit algorithms list (never 'none'), and keep expiry checks on.",
      references=["https://cheatsheetseries.owasp.org/cheatsheets/JSON_Web_Token_for_Java_Cheat_Sheet.html"])
def jwt_unverified(path, text, lines):
    pat = re.compile(r"""["']verify_signature["']\s*:\s*False|["']verify_exp["']\s*:\s*False|jwt\.decode\([^)]*verify\s*=\s*False"""
                     r"""|algorithms\s*[:=]\s*\[\s*["']none["']|ignoreExpiration\s*:\s*true|\bjwt\.decode\(\s*\w+\s*\)""", re.I)
    yield from line_matches(jwt_unverified.info, path, lines, pat)


@rule("ACR-APP-009", "CORS allows any origin together with credentials", Severity.HIGH, "app-security", PY + JS,
      fix="List the exact trusted origins. Never combine a wildcard or reflected origin with credentials (cookies, auth headers).",
      references=["https://developer.mozilla.org/en-US/docs/Web/HTTP/CORS"])
def cors_wildcard(path, text, lines):
    creds = re.compile(r"allow_credentials\s*=\s*True|supports_credentials\s*=\s*True|credentials\s*:\s*true", re.I)
    if not creds.search(text):
        return
    wildcard = re.compile(r"""allow_origins\s*=\s*\[\s*["']\*["']|origins\s*=\s*["']\*["']|origin\s*:\s*(["']\*["']|true)\b"""
                          r"""|CORS\([^)]*resources\s*=\s*\{[^}]*["']origins["']\s*:\s*["']\*["']""")
    yield from line_matches(cors_wildcard.info, path, lines, wildcard)


@rule("ACR-APP-010", "Predictable random numbers used for a secret value", Severity.MEDIUM, "app-security", PY + JS + GO,
      fix="Use a CSPRNG: secrets.token_urlsafe() / secrets.choice() in Python, crypto.randomUUID() or "
          "crypto.getRandomValues() in JavaScript, crypto/rand in Go. random, Math.random and math/rand can be "
          "predicted from earlier outputs.",
      references=["https://cwe.mitre.org/data/definitions/338.html"])
def weak_random(path, text, lines):
    names = r"(?i)\b\w*(token|secret|passw|nonce|otp|salt|session_?id|csrf|api_?key|reset_?code|verification_?code)\w*"
    pat = re.compile(names + r"""["']?\s*[:=][^\n]*(\brandom\.(random|randint|choice|choices|randrange|getrandbits|sample)\(|\bMath\.random\(\))""")
    yield from line_matches(weak_random.info, path, lines, pat)
    # Go: only math/rand's package functions; crypto/rand has Read and Int too, so a file that imports it is left alone
    if '"math/rand"' in text and '"crypto/rand"' not in text:
        go = re.compile(names + r"\s*:?=[^\n]*\brand\.(Int|Intn|Int31|Int31n|Int63|Int63n|Uint32|Uint64|Float64|Read|Perm|Shuffle)\(")
        yield from line_matches(weak_random.info, path, lines, go)


@rule("ACR-APP-011", "XML parser resolves external entities (XXE)", Severity.HIGH, "app-security", PY + JS,
      fix="Parse untrusted XML with defusedxml (Python) or with entity expansion and network access off "
          "(lxml: resolve_entities=False, no_network=True; libxmljs: noent: false).",
      references=["https://cheatsheetseries.owasp.org/cheatsheets/XML_External_Entity_Prevention_Cheat_Sheet.html"])
def xxe(path, text, lines):
    pat = re.compile(r"resolve_entities\s*=\s*True|no_network\s*=\s*False|feature_external_(ges|pes)\s*,\s*(True|1)\b"
                     r"|\bnoent\s*:\s*true\b")
    yield from line_matches(xxe.info, path, lines, pat)


@rule("ACR-APP-012", "Redirect to a URL taken straight from the request (open redirect)", Severity.MEDIUM, "app-security",
      PY + JS + GO,
      fix="Redirect only to relative paths or an allow-list of hosts (e.g. url_has_allowed_host_and_scheme in Django); "
          "otherwise attackers use your domain to send users to phishing pages.",
      references=["https://cheatsheetseries.owasp.org/cheatsheets/Unvalidated_Redirects_and_Forwards_Cheat_Sheet.html"])
def open_redirect(path, text, lines):
    pat = re.compile(r"\b(redirect|HttpResponseRedirect|RedirectResponse)\(\s*request\.(args|GET|POST|form|values|query_params)\b"
                     r"|\bres\.redirect\(\s*(\d{3}\s*,\s*)?req\.(query|params|body)\."
                     r"|\bhttp\.Redirect\(\s*\w+,\s*\w+,\s*(r|req|request)\.(URL\.Query\(\)\.Get|FormValue|PostFormValue|URL\.Query\(\)\[)"
                     r"|\bc\.Redirect\(\s*[\w.]+,\s*c\.(Query|Param|PostForm|DefaultQuery)\(")
    yield from line_matches(open_redirect.info, path, lines, pat)


@rule("ACR-APP-013", "File path taken straight from the request (path traversal)", Severity.HIGH, "app-security", PY + JS + GO,
      fix="Resolve the path under a fixed base directory and reject anything that escapes it (or look files up by id); "
          "Flask's send_from_directory and Express's sendFile({ root }) do this for you.",
      references=["https://owasp.org/www-community/attacks/Path_Traversal"])
def path_traversal(path, text, lines):
    pat = re.compile(r"\b(open|send_file|FileResponse|os\.remove|os\.unlink|shutil\.rmtree)\(\s*(f[\"'][^\"']*\{\s*)?request\."
                     r"(args|GET|POST|form|values|query_params|files)\b"
                     r"|\b(res\.(sendFile|download)|fs\.(readFile|readFileSync|createReadStream|unlink|unlinkSync))\(\s*"
                     r"(`[^`]*\$\{\s*)?req\.(query|params|body)\."
                     # Go: a file call or a path join whose argument is read from the request or the route
                     r"|\b(os\.(Open|ReadFile|Remove|RemoveAll|Create|WriteFile|Stat)|http\.ServeFile|filepath\.Join|path\.Join)\([^\n]*?"
                     r"((r|req|request)\.(URL\.Query\(\)\.Get|FormValue|PostFormValue|URL\.Path|PathValue)\(|mux\.Vars\(|chi\.URLParam\(|"
                     r"c\.(Param|Query|PostForm)\()")
    yield from line_matches(path_traversal.info, path, lines, pat)


@rule("ACR-APP-014", "Deprecated SSL/TLS protocol version allowed", Severity.MEDIUM, "app-security", PY + JS,
      fix="Use the library default (ssl.create_default_context(), Node's defaults) or require TLS 1.2+: "
          "ctx.minimum_version = ssl.TLSVersion.TLSv1_2 / minVersion: 'TLSv1.2'.",
      references=["https://datatracker.ietf.org/doc/html/rfc8996"])
def weak_tls(path, text, lines):
    pat = re.compile(r"\bssl\.PROTOCOL_(SSLv2|SSLv3|TLSv1|TLSv1_1)\b|\bTLSVersion\.(SSLv3|TLSv1|TLSv1_1)\b"
                     r"|\bminVersion\s*:\s*['\"](TLSv1|TLSv1\.1)['\"]|\bsecureProtocol\s*:\s*['\"](SSLv2|SSLv3|TLSv1|TLSv1_1)_method")
    yield from line_matches(weak_tls.info, path, lines, pat)


@rule("ACR-APP-015", "Session or auth cookie without Secure or HttpOnly", Severity.MEDIUM, "app-security", PY + JS,
      fix="Keep Secure (HTTPS only) and HttpOnly (no JavaScript access) on session and auth cookies, plus SameSite=Lax or Strict.",
      references=["https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html#cookies"])
def insecure_cookie(path, text, lines):
    pat = re.compile(r"\b(SESSION|CSRF)_COOKIE_(SECURE|HTTPONLY)\s*=\s*False\b|\bset_cookie\([^)]*\b(secure|httponly)\s*=\s*False"
                     r"|\bhttpOnly\s*:\s*false\b")
    yield from line_matches(insecure_cookie.info, path, lines, pat)


@rule("ACR-APP-016", "Regular expression built from request input (ReDoS)", Severity.MEDIUM, "app-security", PY + JS,
      fix="Escape user input before putting it in a pattern (re.escape / a library such as escape-string-regexp), or use "
          "plain substring matching; a crafted pattern can pin a CPU for minutes.",
      references=["https://owasp.org/www-community/attacks/Regular_expression_Denial_of_Service_-_ReDoS"])
def regex_injection(path, text, lines):
    pat = re.compile(r"\bre\.(compile|search|match|fullmatch|findall|sub|split)\(\s*(f[\"'][^\"']*\{\s*)?request\."
                     r"(args|GET|POST|form|values|query_params|json)\b"
                     r"|\bnew RegExp\(\s*(`[^`]*\$\{\s*)?req\.(query|params|body)\.")
    yield from line_matches(regex_injection.info, path, lines, pat)


@rule("ACR-APP-017", "Django accepts any Host header (ALLOWED_HOSTS wildcard)", Severity.MEDIUM, "app-security", PY,
      fix="List the real hostnames (ALLOWED_HOSTS = [\"api.example.com\"]); with \"*\", forged Host headers poison "
          "password-reset links and caches.",
      references=["https://docs.djangoproject.com/en/stable/ref/settings/#allowed-hosts"])
def django_allowed_hosts(path, text, lines):
    pat = re.compile(r"""^\s*ALLOWED_HOSTS\s*=\s*[\[(][^\])]*["']\*["']""")
    yield from line_matches(django_allowed_hosts.info, path, lines, pat)


@rule("ACR-APP-018", "CSRF protection turned off", Severity.MEDIUM, "app-security", PY,
      fix="Keep CSRF checks on for cookie-authenticated endpoints. Exempt only endpoints that authenticate every request "
          "with a token header (not a cookie), and say so in a comment.",
      references=["https://cheatsheetseries.owasp.org/cheatsheets/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.html"])
def csrf_off(path, text, lines):
    pat = re.compile(r"^\s*@csrf_exempt\b|\bWTF_CSRF_ENABLED\s*[=:]\s*False\b|\bWTF_CSRF_CHECK_DEFAULT\s*[=:]\s*False\b")
    yield from line_matches(csrf_off.info, path, lines, pat)


@rule("ACR-APP-019", "ECDSA private key handled through big.Int arithmetic on its D field", Severity.MEDIUM,
      "app-security", GO,
      fix="Encode and validate keys with `PrivateKey.Bytes()` and build them with `ecdsa.ParseRawPrivateKey` "
          "(Go 1.25+), which check the scalar without big.Int operations whose timing depends on the key.",
      references=["https://pkg.go.dev/crypto/ecdsa#PrivateKey.Bytes",
                  "https://pkg.go.dev/crypto/ecdsa#ParseRawPrivateKey"])
def ecdsa_scalar_big_int(path, text, lines):
    """big.Int is not constant time: comparing, measuring or re-encoding a private scalar with it can leak the key
    through timing, and setting D by hand skips the checks the key constructors make."""
    calls = r"\.D\.(Cmp|CmpAbs|BitLen|Bits|Bytes|FillBytes|Sign|Text|String|Int64|Uint64)\(|\.D\s*=[^=]"
    if '"crypto/ecdsa"' in text:
        pat = re.compile(calls)
    else:
        # The key can come from another package (a wrapper type embedding *ecdsa.PrivateKey), so outside files that
        # import crypto/ecdsa only a receiver named like a key counts.
        pat = re.compile(r"\b\w*(?:[Kk]ey|[Pp]riv|[Ss]igner)\w*(?:\.PrivateKey)?(?:" + calls + ")")
    yield from line_matches(ecdsa_scalar_big_int.info, path, lines, pat)



TEST_DIRS = {"test", "tests", "e2e", "testdata", "testutil", "testing"}


def _is_test(path: str) -> bool:
    *dirs, name = path.split("/")
    return (name.endswith("_test.go") or name.startswith("test_") or name.endswith("_test.py")
            or name == "conftest.py" or bool(TEST_DIRS & set(dirs)))


def _python_strings(text: str) -> list[tuple[int, int]]:
    """Character spans of string literals (docstring examples included), or none if the file doesn't tokenize."""
    starts = [0]
    for line in text.splitlines(keepends=True):
        starts.append(starts[-1] + len(line))
    kinds = {tokenize.STRING} | {getattr(tokenize, k) for k in ("FSTRING_START",) if hasattr(tokenize, k)}
    try:
        return [(starts[tok.start[0] - 1] + tok.start[1], starts[tok.end[0] - 1] + tok.end[1])
                for tok in tokenize.generate_tokens(io.StringIO(text).readline) if tok.type in kinds]
    except (tokenize.TokenError, SyntaxError, IndentationError):
        return []


def _bracketed(text: str, start: int, open_: str, close: str) -> str:
    """Text from `start` (at or before an opening bracket) through its matching close, or to the end if unbalanced."""
    depth, i = 0, text.find(open_, start)
    while 0 <= i < len(text):
        depth += {open_: 1, close: -1}.get(text[i], 0)
        if depth == 0:
            return text[start:i + 1]
        i += 1
    return text[start:]


def _report_spans(info, path, text, lines, spans, detail):
    for pos in spans:
        line = text.count("\n", 0, pos) + 1
        src = lines[line - 1]
        if not ignored(src, info.rule_id) and not src.lstrip().startswith(("#", "//")):
            yield make(info, path, line, detail)


@rule("ACR-APP-020", "Go HTTP request sent without a timeout", Severity.LOW, "app-security", GO,
      fix="Give the client a `Timeout`, or build the request with `http.NewRequestWithContext` and a context from "
          "`context.WithTimeout`; `http.Get`, `http.Post` and `http.DefaultClient` have none.",
      references=["https://pkg.go.dev/net/http#Client", "https://cwe.mitre.org/data/definitions/400.html"])
def go_http_no_timeout(path, text, lines):
    """Go's default client waits forever: a server that accepts the connection and never answers holds the calling
    goroutine, and its connection, until the process exits."""
    if _is_test(path):
        return
    spans = [m.start() for m in re.finditer(r"\bhttp\.(Get|Head|Post|PostForm)\(", text)]
    # A request can carry a deadline, its own or its caller's, so the default client and bare clients only count in
    # files that never attach a context or deadline to one.
    if not re.search(r"\bcontext\.With(Timeout|Deadline)\(|\.SetDeadline\(|NewRequestWithContext\(|\.WithContext\(", text):
        spans += [m.start() for m in re.finditer(r"\bhttp\.DefaultClient\.(Do|Get|Head|Post|PostForm)\(", text)]
        spans += [m.start() for m in re.finditer(r"\bhttp\.Client\{", text)
                  if "Timeout:" not in _bracketed(text, m.start(), "{", "}")]
    yield from _report_spans(go_http_no_timeout.info, path, text, lines, sorted(spans), "")


@rule("ACR-APP-021", "Python HTTP request sent without a timeout", Severity.LOW, "app-security", PY,
      fix="Pass `timeout=` (seconds, or a (connect, read) pair) to every `requests` call and to `urlopen`; both "
          "default to waiting forever.",
      references=["https://requests.readthedocs.io/en/latest/user/advanced/#timeouts",
                  "https://cwe.mitre.org/data/definitions/400.html"])
def py_http_no_timeout(path, text, lines):
    """requests and urllib have no default timeout, so one unresponsive server hangs the worker that called it."""
    if _is_test(path):
        return
    # A bare urlopen( is the imported function; .urlopen( is some other object's method (urllib3's pools have one).
    call = re.compile(r"\brequests\.(get|head|post|put|patch|delete|options|request)\(|\burllib\.request\.urlopen\("
                      r"|(?<![\w.])(?<!def )urlopen\(")
    strings = _python_strings(text)
    spans = [m.start() for m in call.finditer(text)
             if not re.search(r"\btimeout\s*=", _bracketed(text, m.start(), "(", ")"))
             and not any(a <= m.start() < b for a, b in strings)]
    yield from _report_spans(py_http_no_timeout.info, path, text, lines, spans, "")


@rule("ACR-APP-022", "Archive extracted without a path filter (zip slip)", Severity.MEDIUM, "app-security", PY,
      fix="Extract with `tar.extractall(path, filter=\"data\")` (Python 3.12+, backported to 3.8.17/3.9.17/3.10.12/3.11.4)"
          " and check each zip member's resolved path stays under the target before `ZipFile.extractall`. An archive "
          "member named `../../etc/cron.d/x` or a symlink out of the tree otherwise writes wherever it points.",
      references=["https://docs.python.org/3/library/tarfile.html#tarfile-extraction-filter",
                  "https://cwe.mitre.org/data/definitions/22.html"])
def archive_extract_unfiltered(path, text, lines):
    """Model and dataset downloads are archives from somewhere else; tarfile only refuses escaping members when asked."""
    if _is_test(path):
        return
    # extractall on anything; extract only on a receiver named like an archive (propagators and SQL functions have
    # extract methods too)
    call = re.compile(r"\.extractall\(|\b\w*(?:tar|zip|archive|tf|zf)\w*\.extract\(", re.I)
    strings = _python_strings(text)
    spans = []
    for m in call.finditer(text):
        if any(a <= m.start() < b for a, b in strings):
            continue
        args = _bracketed(text, m.start(), "(", ")")
        if re.search(r"\bfilter\s*=", args):
            continue
        # a member path checked against the target directory on the lines just above counts as filtered
        before = text[max(0, m.start() - 600):m.start()]
        if re.search(r"(realpath|resolve|abspath|commonpath|is_relative_to|startswith)\(", before):
            continue
        spans.append(m.start())
    yield from _report_spans(archive_extract_unfiltered.info, path, text, lines, spans, "")


@rule("ACR-APP-023", "Temporary file created by name, open to a race (mktemp)", Severity.MEDIUM, "app-security", PY + GO,
      fix="Create and open the file in one step: `tempfile.NamedTemporaryFile` / `mkstemp` / `TemporaryDirectory` in "
          "Python, `os.CreateTemp` / `os.MkdirTemp` in Go. A name picked first can be claimed by another process (or a "
          "symlink planted at it) before the file is opened, so the write lands where the attacker chose.",
      references=["https://cwe.mitre.org/data/definitions/377.html",
                  "https://docs.python.org/3/library/tempfile.html#tempfile.mktemp"])
def predictable_temp_file(path, text, lines):
    if _is_test(path):
        return
    pat = re.compile(r"\btempfile\.mktemp\(|\bos\.path\.join\(\s*(tempfile\.gettempdir\(\)|\"/tmp\"|'/tmp')\s*,\s*[\"']\w"
                     r"""|\bopen\(\s*[\"']/tmp/\w[^\"']*[\"']\s*,\s*[\"']w|\bfilepath\.Join\(os\.TempDir\(\),\s*"\w|\bos\.(Create|WriteFile)\("/tmp/\w""")
    yield from line_matches(predictable_temp_file.info, path, lines, pat)


@rule("ACR-APP-024", "Go HTTP server with no request timeouts", Severity.MEDIUM, "app-security", GO,
      fix="Serve from an `http.Server` that sets `ReadHeaderTimeout` (and usually `ReadTimeout`, `WriteTimeout`, "
          "`IdleTimeout`): `http.ListenAndServe` and a server without them hold a connection open for as long as a "
          "slow client keeps sending headers, so a few hundred idle sockets exhaust the listener (Slowloris).",
      references=["https://pkg.go.dev/net/http#Server", "https://cwe.mitre.org/data/definitions/400.html"])
def go_server_no_timeouts(path, text, lines):
    if _is_test(path):
        return
    spans = [m.start() for m in re.finditer(r"\bhttp\.ListenAndServe(TLS)?\(", text)]
    spans += [m.start() for m in re.finditer(r"\bhttp\.Server\{", text)
              if not re.search(r"\b(ReadHeaderTimeout|ReadTimeout):", _bracketed(text, m.start(), "{", "}"))]
    yield from _report_spans(go_server_no_timeouts.info, path, text, lines, sorted(spans), "")


@rule("ACR-APP-025", "File or directory created world-writable", Severity.MEDIUM, "app-security", PY + GO,
      fix="Use the narrowest mode that works: 0o600 for files only this user reads, 0o644 for files others may read, "
          "0o700 or 0o755 for directories. Mode 0777 or 0666 lets any local user replace the content, which for a "
          "config, key or script the program later reads is code execution.",
      references=["https://cwe.mitre.org/data/definitions/732.html"])
def world_writable_mode(path, text, lines):
    if _is_test(path):
        return
    # any call whose mode argument is octal 777/666/ends in 7 or 6 for others: chmod, mkdir, open, WriteFile, MkdirAll
    pat = re.compile(r"\b(os\.(chmod|mkdir|makedirs|open|fchmod|mkfifo|mknod|umask)|os\.(Chmod|Mkdir|MkdirAll|WriteFile|OpenFile)|"
                     r"ioutil\.WriteFile|Path\([^)]*\)\.(chmod|mkdir|touch)|\.chmod|\.mkdir|\.touch)\([^)\n]*?\b0o?[0-7]*[67][67]?[67]\b")
    # a leading 0 in Go, 0o in Python; the last digit is "others", so any mode ending in 6 or 7 is world-writable
    strict = re.compile(r"\b0o?[0-7]{0,2}[67]\b(?![.\d])")
    for i, line in enumerate(lines, start=1):
        m = pat.search(line)
        if not m or ignored(line, world_writable_mode.info.rule_id) or line.lstrip().startswith(("#", "//")):
            continue
        modes = [x for x in strict.findall(line) if x.lstrip("0o")[-1] in "67" and len(x.lstrip("0o")) in (3, 4)]
        if modes:
            yield make(world_writable_mode.info, path, i, f"mode {modes[0]} lets any user write it.")


@rule("ACR-APP-026", "Authorisation checked with assert", Severity.HIGH, "app-security", PY,
      fix="Raise or return on the failed check (`if not user.is_admin: raise PermissionDenied`). Python drops every "
          "`assert` when run with -O or PYTHONOPTIMIZE, which production images sometimes set, and the check "
          "disappears with it.",
      references=["https://cwe.mitre.org/data/definitions/617.html",
                  "https://docs.python.org/3/reference/simple_stmts.html#the-assert-statement"])
def assert_for_authorisation(path, text, lines):
    """An assert that names a user, role, permission, token or ownership is a security check written as a debug aid."""
    if _is_test(path):
        return
    pat = re.compile(r"^\s*assert\b[^\n]*\b(is_(authenticated|admin|staff|superuser|owner|active|verified)|has_(perm|perms|role|permission|access)|"
                     r"can_(read|write|edit|delete|view|access)|permissions?|authoriz\w*|authent\w*|is_allowed|allowed|roles?|token|api_key|owner_id|user_id"
                     r"|current_user|request\.user|scopes?)\b", re.I)
    yield from line_matches(assert_for_authorisation.info, path, lines, pat)
