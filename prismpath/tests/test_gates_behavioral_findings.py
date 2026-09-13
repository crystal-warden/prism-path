# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Crystal Warden Supply Chain Labs LLC
"""A control the gate cannot click is a finding, not silence.

Found in the September 2026 readability review: behavioral_check swallowed five exceptions, so a
button that never became clickable left `interacted` False and the gate reported a clean pass. The
browser is faked here on purpose: playwright is installed in the venv but the chromium binary is
not, and these are assertions about the gate's reporting, not about a real page.
"""
import pytest

pytest.importorskip("playwright")

from playwright.sync_api import Error as PlaywrightError

from prismpath.orchestration import gates


class FakeElement:
    """One DOM node. `click_error` makes the click fail the way a covered control does."""

    def __init__(self, text="go", click_error=None, visible=True):
        self.text = text
        self.click_error = click_error
        self.visible = visible
        self.filled = None
        self.clicked = False

    def inner_text(self):
        return self.text

    def is_visible(self):
        return self.visible

    def fill(self, value):
        if self.click_error is not None:
            raise PlaywrightError("element is not editable")
        self.filled = value

    def click(self, timeout=None):
        if self.click_error is not None:
            raise PlaywrightError(self.click_error)
        self.clicked = True


class FakePage:
    """Enough of the playwright page surface for the behavioral gate, and nothing more."""

    def __init__(self, buttons=(), cells=(), field=None, text_after_click=None):
        self.buttons = list(buttons)
        self.cells = list(cells)
        self.field = field
        self.text = "before"
        self.text_after_click = text_after_click

    def on(self, event, handler):
        pass

    def add_init_script(self, script):
        pass

    def goto(self, url, wait_until=None, timeout=None):
        pass

    def wait_for_timeout(self, milliseconds):
        for element in self.buttons + self.cells:
            if element.clicked and self.text_after_click is not None:
                self.text = self.text_after_click

    def query_selector(self, selector):
        if selector == "input, textarea":
            return self.field
        return None

    def query_selector_all(self, selector):
        if selector == "button":
            return list(self.buttons)
        if selector in gates.CELL_SELECTORS:
            return list(self.cells)
        return []

    def evaluate(self, expression):
        if "innerText" in expression:
            return self.text
        return []


class FakeBrowser:
    def __init__(self, page):
        self.page = page
        self.closed = False

    def new_page(self):
        return self.page

    def close(self):
        self.closed = True


class FakePlaywright:
    def __init__(self, page):
        self.chromium = self
        self.page = page
        self.browser = FakeBrowser(page)

    def launch(self, headless=True):
        return self.browser

    def __enter__(self):
        return self

    def __exit__(self, *ignored_args):
        return False


def _run_against(monkeypatch, tmp_path, page):
    (tmp_path / "index.html").write_text("<html><body><button>go</button></body></html>")
    import playwright.sync_api
    monkeypatch.setattr(playwright.sync_api, "sync_playwright", lambda: FakePlaywright(page))
    return gates.behavioral_check(str(tmp_path))


def test_unclickable_primary_control_is_reported(tmp_path, monkeypatch):
    page = FakePage(buttons=[FakeElement(click_error="intercepts pointer events")])
    errs = _run_against(monkeypatch, tmp_path, page)
    assert any("primary control could not be clicked" in error for error in errs)
    assert any("intercepts pointer events" in error for error in errs)


def test_unclickable_grid_cell_is_reported(tmp_path, monkeypatch):
    cell = FakeElement(text="", click_error="element is outside of the viewport")
    page = FakePage(buttons=[FakeElement()], cells=[cell])
    errs = _run_against(monkeypatch, tmp_path, page)
    assert any("grid cell could not be clicked" in error for error in errs)
    assert any("outside of the viewport" in error for error in errs)


def test_a_field_that_refuses_text_is_not_a_finding(tmp_path, monkeypatch):
    """The gate types into the first field only to give the click something to submit."""
    readonly_field = FakeElement(text="", click_error="element is not editable")
    page = FakePage(buttons=[FakeElement()], field=readonly_field, text_after_click="after")
    errs = _run_against(monkeypatch, tmp_path, page)
    assert errs == [], errs


def test_a_dead_button_still_reports_no_visible_change(tmp_path, monkeypatch):
    """The split must not lose the original finding: clicked, and nothing anywhere moved."""
    page = FakePage(buttons=[FakeElement()])
    errs = _run_against(monkeypatch, tmp_path, page)
    assert any("NO visible change" in error for error in errs)
    assert all(error.startswith("[behavioral] ") for error in errs)


def test_a_reacting_page_passes(tmp_path, monkeypatch):
    page = FakePage(buttons=[FakeElement()], text_after_click="after")
    errs = _run_against(monkeypatch, tmp_path, page)
    assert errs == [], errs
