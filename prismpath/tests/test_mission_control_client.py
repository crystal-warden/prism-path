# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Crystal Warden Supply Chain Labs LLC
"""Mission Control's browser client against its two contracts, the page and the API.

The client addresses elements only through `static/js/ids.mjs` and requests only through
`static/js/paths.mjs`. These tests hold those two tables to `index.html` and to the app's OpenAPI
document, parse every module the way a browser does (ES modules are strict mode code), and run the
client's own `node --test` suite. The tests that need node skip when it is absent; CI's conformance
and mission_control jobs both have it.
"""
import os
import re
import shutil
import subprocess
from html.parser import HTMLParser
from pathlib import Path

import pytest

STATIC = Path(__file__).resolve().parents[1] / "mission_control" / "static"
JS = STATIC / "js"
NODE = shutil.which("node")
needs_node = pytest.mark.skipif(NODE is None, reason="node is not installed")


def _modules():
    return sorted(JS.glob("*.mjs"))


def _table(module: str, name: str) -> dict:
    """The `name: "value",` entries of the frozen object `name` in a client module."""
    text = (JS / module).read_text(encoding="utf-8")
    block = re.search(r"export const " + name + r" = Object\.freeze\(\{(.*?)\n\}\);", text, re.S)
    assert block, f"{module} has no {name} table"
    entries = dict(re.findall(r'^\s*(\w+): "([^"]+)",\s*$', block.group(1), re.M))
    lines = [line for line in block.group(1).splitlines() if line.strip() and not line.strip().startswith("//")]
    assert len(entries) == len(lines), f"{module} {name}: an entry is not on one `name: \"value\",` line"
    return entries


def _write_routes() -> set:
    text = (JS / "paths.mjs").read_text(encoding="utf-8")
    block = re.search(r"export const WRITE_ROUTES = Object\.freeze\(\[(.*?)\]\);", text, re.S)
    assert block, "paths.mjs has no WRITE_ROUTES"
    return set(re.findall(r'"((?:GET|POST|PUT|PATCH|DELETE) /[^"]*)"', block.group(1)))


class _PageElements(HTMLParser):
    def __init__(self):
        super().__init__()
        self.ids, self.tags = [], []

    def handle_starttag(self, tag, attrs):
        attributes = dict(attrs)
        self.tags.append((tag, attributes))
        if "id" in attributes:
            self.ids.append(attributes["id"])


def _page() -> _PageElements:
    parser = _PageElements()
    parser.feed((STATIC / "index.html").read_text(encoding="utf-8"))
    return parser


def test_the_old_single_file_client_is_gone():
    assert not (STATIC / "app.js").exists()
    assert {path.name for path in _modules()} >= {
        "markup.mjs", "transport.mjs", "state.mjs", "events.mjs", "graph.mjs", "authoring.mjs",
        "operating.mjs", "auditing.mjs", "main.mjs", "ids.mjs", "paths.mjs"}


def test_every_id_in_ids_mjs_exists_in_index_html():
    page = _page()
    assert len(page.ids) == len(set(page.ids)), "index.html declares an id twice"
    missing = sorted(set(_table("ids.mjs", "IDS").values()) - set(page.ids))
    assert not missing, f"ids.mjs names elements index.html does not declare: {missing}"


def test_no_module_addresses_an_element_or_a_route_by_a_literal():
    literal_id = re.compile(r"""getElementById\(\s*["'`]|querySelector(?:All)?\(\s*["'`][^"'`]*#""")
    literal_path = re.compile(r"""\b(?:getJson|postJson|openStream|runTool)\(\s*["'`]/|bindAction\([^;]*?"[A-Z]+",\s*["'`]/""")
    for module in _modules():
        if module.name in ("ids.mjs", "paths.mjs"):
            continue
        text = module.read_text(encoding="utf-8")
        assert not literal_id.search(text), f"{module.name} addresses an element by a literal id"
        assert not literal_path.search(text), f"{module.name} requests a literal path"


def test_every_screen_tab_has_its_view_and_its_screen_entry():
    page = _page()
    tabs = [attributes for tag, attributes in page.tags if "data-screen" in attributes]
    screens = re.findall(r'\{ screen: "(\w+)", interface: "(\w+)", view: IDS\.(\w+)', (JS / "main.mjs").read_text(encoding="utf-8"))
    ids = _table("ids.mjs", "IDS")
    assert {(tab["data-screen"], tab["data-interface"]) for tab in tabs} == {(screen, face) for screen, face, _ in screens}
    for screen, _, view in screens:
        assert ids[view] == "v-" + screen and ids[view] in page.ids, screen
    interfaces = [attributes["data-interface"] for tag, attributes in page.tags
                  if "data-interface" in attributes and "data-screen" not in attributes]
    assert interfaces == ["authoring", "operating", "auditing"]


def test_the_page_runs_only_the_consoles_own_scripts_and_no_inline_style():
    page = _page()
    scripts = [attributes for tag, attributes in page.tags if tag == "script"]
    assert scripts == [{"src": "/vendor/cytoscape.min.js"}, {"type": "module", "src": "/js/main.mjs"}]
    for tag, attributes in page.tags:
        assert "style" not in attributes, (tag, attributes)
        assert not [name for name in attributes if name.startswith("on")], (tag, attributes)
    assert not [tag for tag, _ in page.tags if tag == "style"]
    for module in _modules():
        # the content security policy refuses an inline style attribute in rendered markup
        assert not re.search(r"""style\s*=\s*["'`]""", module.read_text(encoding="utf-8")), module.name


@needs_node
@pytest.mark.parametrize("module", [path.name for path in sorted(JS.glob("*.mjs")) + sorted((JS / "tests").glob("*.mjs"))]
                         if JS.is_dir() else ["missing"])
def test_every_module_parses_as_strict_module_code(module):
    path = JS / module if (JS / module).exists() else JS / "tests" / module
    # A .mjs file is parsed as an ES module, which is strict mode code throughout.
    result = subprocess.run([NODE, "--check", str(path)], capture_output=True, text=True, timeout=60)
    assert result.returncode == 0, result.stderr


@needs_node
def test_the_client_node_suite_passes():
    tests = sorted(str(path) for path in (JS / "tests").glob("*.test.mjs"))
    assert tests, "the client has no node tests"
    result = subprocess.run([NODE, "--test", *tests], capture_output=True, text=True, timeout=300,
                            env={**os.environ, "NODE_NO_WARNINGS": "1"})
    assert result.returncode == 0, result.stdout[-4000:] + result.stderr[-2000:]


# The API side needs the control-plane extra.
def _app():
    pytest.importorskip("fastapi")
    from prismpath.mission_control.app import create_app
    return create_app(read_only=False)


def test_every_path_in_paths_mjs_exists_in_the_openapi_document():
    from prismpath.mission_control.app import API_PREFIX
    schema = _app().openapi()["paths"]
    missing = sorted(path for path in _table("paths.mjs", "PATHS").values() if API_PREFIX + path not in schema)
    assert not missing, f"paths.mjs requests paths the console does not serve: {missing}"


def test_write_routes_in_paths_mjs_are_exactly_the_write_routes_the_client_uses():
    from prismpath.mission_control.app import API_PREFIX
    from prismpath.mission_control.posture import CAPABILITY_KEY
    schema = _app().openapi()["paths"]
    used = set(_table("paths.mjs", "PATHS").values())
    declared = {f"{method.upper()} {path[len(API_PREFIX):]}" for path, operations in schema.items()
                for method, operation in operations.items()
                if path[len(API_PREFIX):] in used and operation.get(CAPABILITY_KEY) == "write"}
    assert _write_routes() == declared


@pytest.mark.parametrize("read_only, posture", [(False, "full"), (True, "read-only")])
def test_the_page_carries_the_posture_and_the_modules_are_javascript(read_only, posture):
    pytest.importorskip("fastapi")
    from fastapi.testclient import TestClient
    from prismpath.mission_control import core
    from prismpath.mission_control.app import create_app
    application = create_app(read_only=read_only)
    client = TestClient(application, base_url=f"http://127.0.0.1:{core.SETTINGS.port}")
    page = client.get("/").text
    assert f'<meta name="prismpath-posture" content="{posture}">' in page
    assert '<meta name="prismpath-posture" content="">' in (STATIC / "index.html").read_text(encoding="utf-8")
    for module in _modules():
        response = client.get("/js/" + module.name)
        assert response.status_code == 200, module.name
        assert response.headers["content-type"].split(";")[0] in ("text/javascript", "application/javascript"), module.name
