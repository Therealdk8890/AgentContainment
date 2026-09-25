from pathlib import Path

import pytest

from agent_containment.bootstrap import (
    BootstrapAdmissionError,
    require_controller_available,
)


def test_bootstrap_admission_fails_closed_when_controller_socket_is_missing(tmp_path: Path):
    with pytest.raises(BootstrapAdmissionError, match="unavailable"):
        require_controller_available(tmp_path / "missing.sock")


def test_bootstrap_admission_rejects_unreachable_socket(tmp_path: Path):
    socket_path = tmp_path / "controller.sock"
    socket_path.touch()

    with pytest.raises(BootstrapAdmissionError, match="unavailable"):
        require_controller_available(socket_path)
