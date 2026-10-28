"""Explicit test-only adapter. Production loading never imports this module."""
from pathlib import Path

import pytest

from opendbc import DBC_PATH, get_generated_dbcs
from opendbc.can import dbc_asset


@pytest.fixture
def sienna_dbc_adapter(monkeypatch):
  def load(name):
    source = dbc_asset.SOURCES[name]
    generated = get_generated_dbcs()
    return generated[source] if source in generated else (Path(DBC_PATH) / (source + '.dbc')).read_text()

  monkeypatch.setattr(dbc_asset, 'load_protected_dbc', load)
