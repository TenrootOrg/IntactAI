"""The Velociraptor organization every Velociraptor query runs in.

The UI's top-bar org dropdown sets the `velo_org` cookie. A before_request hook
puts it in a ContextVar, and every Velociraptor channel is wrapped (wrap()) so
each Query carries it as VQLCollectorArgs.org_id. That keeps the ~60 query sites
untouched: they all build a VQLCollectorArgs and call Query on one of the
channels the helpers here wrap.

Work that runs outside the request keeps the org it was started in:
- threads and executor jobs inherit it (install_thread_inheritance()); only this
  one var is carried over, NOT Flask's request context;
- work that runs later from a stored record (a schedule, a case's adopted hunt)
  stores current() with the record and re-enters it with use(org).

Empty / 'root' means the root org, which is what every query ran in before.
"""
import contextlib
import contextvars
import re
import threading
from concurrent.futures import ThreadPoolExecutor

_org = contextvars.ContextVar("velo_org", default="")
COOKIE = "velo_org"
# Velociraptor org ids are short base32-ish ids ('OFM5G') or 'root'.
_VALID = re.compile(r"^[A-Za-z0-9_.-]{1,64}$")


def clean(org):
    org = (org or "").strip()
    if not org or org == "root" or not _VALID.match(org):
        return ""
    return org


def current():
    """The org id to query ('' = root)."""
    return _org.get()


def set_current(org):
    return _org.set(clean(org))


@contextlib.contextmanager
def use(org):
    """Run a block in `org` ('' / 'root' / None = root)."""
    tok = _org.set(clean(org))
    try:
        yield
    finally:
        _org.reset(tok)


def root():
    """Run a block in the root org: server-wide things (artifact / tool uploads,
    client package builds) must not follow the operator's dropdown."""
    return use("")


def in_root(fn):
    """Decorator: `fn` always runs in the root org (see root())."""
    import functools

    @functools.wraps(fn)
    def run(*a, **k):
        with root():
            return fn(*a, **k)
    return run


# --- gRPC ----------------------------------------------------------------------
try:
    import grpc

    class _OrgInterceptor(grpc.UnaryStreamClientInterceptor, grpc.UnaryUnaryClientInterceptor):
        def __init__(self, org):
            self.org = org

        def _stamp(self, request):
            if self.org and hasattr(request, "org_id") and not request.org_id:
                request.org_id = self.org
            return request

        def intercept_unary_stream(self, continuation, details, request):
            return continuation(details, self._stamp(request))

        def intercept_unary_unary(self, continuation, details, request):
            return continuation(details, self._stamp(request))

    def wrap(channel, org=None):
        """A Velociraptor channel whose Query requests carry `org` (default:
        current(), read NOW). Captured at channel creation, not per RPC: several
        workers make the stub in one thread and query from a pool thread."""
        if channel is None:
            return None
        org = current() if org is None else clean(org)
        return grpc.intercept_channel(channel, _OrgInterceptor(org)) if org else channel
except (ImportError, TypeError, AttributeError):   # unit tests: no grpc, or the stub module
    def wrap(channel, org=None):
        return channel


def cli_args(org=None):
    """`velociraptor ... query` flags for the docker-exec callers."""
    org = current() if org is None else clean(org)
    return ["--org", org] if org else []


def datastore(org=None):
    """The org's datastore root inside the Velociraptor container: root's is
    /var./, every other org's is /var./orgs/<id>/ (checked on 0.77.3)."""
    org = current() if org is None else clean(org)
    return f"/var./orgs/{org}/" if org else "/var./"


def of_run(run):
    """The org a stored automation run was started in (its details.velo_org)."""
    d = (run or {}).get("details") if isinstance(run, dict) else None
    if isinstance(d, str):
        try:
            import json
            d = json.loads(d)
        except ValueError:
            d = None
    return clean((d or {}).get("velo_org"))


# --- threads ---------------------------------------------------------------------
_installed = False


def install_thread_inheritance():
    """New threads and ThreadPoolExecutor jobs start in the org of the code that
    started them. Python 3.11 threads begin with an empty context, so without this
    a hunt or import launched in org X from a request would run in root.
    ponytail: patches Thread.start / ThreadPoolExecutor.submit; drop for
    Thread(context=...) once the image is on Python 3.14."""
    global _installed
    if _installed:
        return
    _installed = True
    orig_start = threading.Thread.start
    orig_submit = ThreadPoolExecutor.submit

    def start(self):
        org = _org.get()
        if org:
            run = self.run

            def run_in_org():
                _org.set(org)
                run()
            self.run = run_in_org
        return orig_start(self)

    def submit(self, fn, /, *args, **kwargs):
        org = _org.get()
        if org:
            inner = fn

            def fn(*a, **k):
                with use(org):
                    return inner(*a, **k)
        return orig_submit(self, fn, *args, **kwargs)

    threading.Thread.start = start
    ThreadPoolExecutor.submit = submit
