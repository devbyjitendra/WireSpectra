import os
import json
import sys
import pytest
from click.testing import CliRunner

# Add src directory to path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..', 'src')))

from main import main

def test_cli_json_options():
    runner = CliRunner()
    result = runner.invoke(main, ["--help"])
    assert result.exit_code == 0
    assert "--export-json" in result.output
