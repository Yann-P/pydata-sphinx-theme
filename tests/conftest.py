"""Configuration of the pytest session."""

import re
import time

from collections.abc import Callable
from http.client import HTTPConnection
from os import environ
from pathlib import Path
from shutil import copytree
from subprocess import PIPE, Popen
from typing import Self

import pytest

from bs4 import BeautifulSoup
from sphinx.testing.util import SphinxTestApp


pytest_plugins = "sphinx.testing.fixtures"

tests_path = Path(__file__).parent
repo_path = tests_path.parent
docs_build_path = repo_path / "docs" / "_build" / "html"

# -- Utils method ------------------------------------------------------------


def escape_ansi(string: str) -> str:
    """Helper function to remove ansi coloring from sphinx warnings."""
    ansi_escape = re.compile(r"(\x9B|\x1B\[)[0-?]*[ -\/]*[@-~]")
    return ansi_escape.sub("", string)


# -- global fixture to build sphinx tmp docs ---------------------------------


class SphinxBuild:
    """Helper class to build a test documentation."""

    def __init__(self, app: SphinxTestApp, src: Path):
        self.app = app
        self.src = src

    def build(self, no_warning: bool = True) -> Self:
        """Build the application."""
        self.app.build()
        if no_warning is True:
            assert self.warnings == "", self.status
        return self

    @property
    def status(self) -> str:
        """Returns the status of the current build."""
        return self.app._status.getvalue()

    @property
    def warnings(self) -> str:
        """Returns the warnings raised by the current build."""
        return self.app._warning.getvalue()

    @property
    def outdir(self) -> Path:
        """Returns the output directory of the current build."""
        return Path(self.app.outdir)

    def html_tree(self, *path) -> str:
        """Returns the html tree of the current build."""
        path_page = self.outdir.joinpath(*path)
        if not path_page.exists():
            raise ValueError(f"{path_page} does not exist")
        return BeautifulSoup(path_page.read_text("utf8"), "html.parser")


@pytest.fixture()
def sphinx_build_factory(make_app: Callable, tmp_path: Path, request) -> Callable:
    """Return a factory builder pointing to the tmp directory."""

    def _func(src_folder: str, **kwargs) -> SphinxBuild:
        """Create the Sphinxbuild from the source folder."""
        no_temp = environ.get("PST_TEST_HTML_DIR")
        nonlocal tmp_path
        if no_temp is not None:
            tmp_path = Path(no_temp) / request.node.name / str(src_folder)
        srcdir = tmp_path / src_folder
        copytree(tests_path / "sites" / src_folder, tmp_path / src_folder)
        app = make_app(srcdir=srcdir, **kwargs)
        return SphinxBuild(app, tmp_path / src_folder)

    yield _func


@pytest.fixture(scope="module")
def url_base():
    """Start local server on built docs and return the localhost URL as the base URL."""
    # Use a port that is not commonly used during development or else you will
    # force the developer to stop running their dev server in order to run the
    # tests.
    port = "8213"
    host = "localhost"
    url = f"http://{host}:{port}"

    # Try starting the server
    process = Popen(
        ["python", "-m", "http.server", port, "--directory", docs_build_path],
        stdout=PIPE,
    )

    # Try connecting to the server
    retries = 5
    while retries > 0:
        conn = HTTPConnection(host, port)
        try:
            conn.request("HEAD", "/")
            response = conn.getresponse()
            if response is not None:
                yield url
                break
        except ConnectionRefusedError:
            time.sleep(1)
            retries -= 1

    # If the code above never yields a URL, then we were never able to connect
    # to the server and retries == 0.
    if not retries:
        raise RuntimeError("Failed to start http server in 5 seconds")
    else:
        # Otherwise the server started and this fixture is done now and we clean
        # up by stopping the server.
        process.terminate()
        process.wait()


# External URLs the docs fetch at runtime, served from local files instead
_LOCAL_COPIES = {
    "https://raw.githubusercontent.com/pydata/pydata-sphinx-theme/main/docs/_templates/custom-template.html": (  # noqa: E501
        repo_path / "docs" / "_templates" / "custom-template.html"
    ),
    "https://pydata-sphinx-theme.readthedocs.io/en/latest/_static/switcher.json": (
        repo_path / "docs" / "_static" / "switcher.json"
    ),
}

# External URLs still allowed, as they load scripts that render tested content:
# MathJax, and the ipywidgets with require.js and widget modules like ipyleaflet
_ALLOWED_URL_PREFIXES = (
    "https://cdn.jsdelivr.net/npm/",
    "https://cdnjs.cloudflare.com/ajax/libs/require.js/",
)


def _handle_external_request(route) -> None:
    url = route.request.url
    if url in _LOCAL_COPIES:
        route.fulfill(path=_LOCAL_COPIES[url])
    elif url.startswith(_ALLOWED_URL_PREFIXES):
        route.continue_()
    else:
        route.abort()


@pytest.fixture
def context(context):
    """Playwright's browser context, with external requests blocked or served locally.

    External requests make tests slow and flaky, as a single hanging request
    (e.g. a placeholder image) delays the page's load event that page.goto
    waits for.

    See https://docs.pytest.org/en/stable/how-to/fixtures.html#override-a-fixture-on-a-directory-conftest-level
    and https://playwright.dev/python/docs/network#abort-requests.
    """
    # Only intercept requests to other hosts than the local test servers
    context.route(
        re.compile(r"^https?://(?!(127\.0\.0\.1|localhost)[:/])"),
        _handle_external_request,
    )
    return context
