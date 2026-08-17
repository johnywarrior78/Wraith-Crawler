from __future__ import annotations

from pathlib import Path

from wraith_crawler.doctor import Doctor
from wraith_crawler.tool_identity import projectdiscovery_httpx_version, strip_ansi


def test_projectdiscovery_current_version_is_distinct_from_python_httpx() -> None:
    assert projectdiscovery_httpx_version("[INF] Current Version: v1.7.2") == "1.7.2"
    assert projectdiscovery_httpx_version("projectdiscovery.io httpx version v1.8.0") == "1.8.0"
    assert projectdiscovery_httpx_version("The httpx command line client 0.28.1") is None


def test_ansi_is_removed_from_tool_diagnostics() -> None:
    assert strip_ansi("\x1b[31mERR\x1b[0m") == "ERR"


def test_doctor_uses_tool_specific_successful_version_flag(tmp_path: Path) -> None:
    retire = tmp_path / "retire"
    retire.write_text(
        "#!/bin/bash\n"
        "if [[ $1 == --version ]]; then printf '5.4.3\\n'; exit 0; fi\n"
        "printf 'error: unknown option\\n' >&2\n"
        "exit 1\n"
    )
    retire.chmod(0o755)

    assert Doctor._version("retire", str(retire)) == "5.4.3"


def test_doctor_does_not_treat_error_output_as_a_version(tmp_path: Path) -> None:
    katana = tmp_path / "katana"
    katana.write_text("#!/bin/bash\nprintf 'FTL permission denied\\n' >&2\nexit 1\n")
    katana.chmod(0o755)

    assert Doctor._version("katana", str(katana)) == ""
