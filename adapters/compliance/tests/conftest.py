"""Path + fixture setup for the compliance-adapter test suite."""
import os, sys
import pytest

HERE = os.path.dirname(os.path.abspath(__file__))
ADAPTER = os.path.dirname(HERE)
for p in ("/home/cwadmin/cwprojects/prismpath", ADAPTER, HERE):
    if p not in sys.path:
        sys.path.insert(0, p)


@pytest.fixture(autouse=True)
def _reset_standard():
    """Keep standard-switching tests from leaking the active catalog into others."""
    yield
    try:
        import compliance_adapter as ca
        ca._ACTIVE = "nist_800171_r2"
    except Exception:
        pass


@pytest.fixture
def records():
    from sample import record
    return [record("3.1.1", "Access Control Policy", "met"),
            record("3.1.5", "Least Privilege", "not-met", ["3.1.5[a]", "3.1.5[b]"]),
            record("3.1.12", "Monitor Remote Access", "partially-met", ["3.1.12[b]"])]


@pytest.fixture
def iso_defer(tmp_path):
    """Isolate the adapter's module-level deferral store to a tmp dir so tests don't share state."""
    import compliance_adapter as ca
    from prismpath import deferral
    orig = ca._DEFER
    ca._DEFER = deferral.FileDeferralStore(str(tmp_path / "deferrals"))
    yield ca._DEFER
    ca._DEFER = orig
