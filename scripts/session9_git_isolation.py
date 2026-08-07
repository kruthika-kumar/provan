from __future__ import annotations

import contextlib
import os
import tempfile
from pathlib import Path
from typing import Iterator


@contextlib.contextmanager
def isolated_git_environment(repository: Path | None = None) -> Iterator[None]:
    """Give validation subprocesses a deterministic, credential-free Git environment."""
    keys = {
        "HOME", "USERPROFILE", "XDG_CONFIG_HOME", "GIT_CONFIG_NOSYSTEM",
        "GIT_CONFIG_GLOBAL", "GIT_CONFIG_SYSTEM", "GIT_TERMINAL_PROMPT",
        "GIT_ASKPASS", "GIT_OPTIONAL_LOCKS", "GIT_NO_REPLACE_OBJECTS",
        "GIT_CONFIG_COUNT", "GIT_CONFIG_KEY_0", "GIT_CONFIG_VALUE_0",
        "GIT_CONFIG_KEY_1", "GIT_CONFIG_VALUE_1", "GIT_CONFIG_KEY_2",
        "GIT_CONFIG_VALUE_2", "GIT_CONFIG_KEY_3", "GIT_CONFIG_VALUE_3",
        "GIT_CONFIG_KEY_4", "GIT_CONFIG_VALUE_4",
    }
    previous = {key: os.environ.get(key) for key in keys}
    with tempfile.TemporaryDirectory(prefix="provan-validation-git-") as temporary:
        root = Path(temporary)
        xdg = root / "xdg"
        hooks = root / "disabled-hooks"
        xdg.mkdir()
        hooks.mkdir()
        os.environ.update({
            "HOME": str(root),
            "USERPROFILE": str(root),
            "XDG_CONFIG_HOME": str(xdg),
            "GIT_CONFIG_NOSYSTEM": "1",
            "GIT_CONFIG_GLOBAL": os.devnull,
            "GIT_CONFIG_SYSTEM": os.devnull,
            "GIT_TERMINAL_PROMPT": "0",
            "GIT_ASKPASS": "",
            "GIT_OPTIONAL_LOCKS": "0",
            "GIT_NO_REPLACE_OBJECTS": "1",
            "GIT_CONFIG_COUNT": "5" if repository is not None else "4",
            "GIT_CONFIG_KEY_0": "core.excludesFile",
            "GIT_CONFIG_VALUE_0": os.devnull,
            "GIT_CONFIG_KEY_1": "core.hooksPath",
            "GIT_CONFIG_VALUE_1": str(hooks),
            "GIT_CONFIG_KEY_2": "core.autocrlf",
            "GIT_CONFIG_VALUE_2": "false",
            "GIT_CONFIG_KEY_3": "core.safecrlf",
            "GIT_CONFIG_VALUE_3": "false",
        })
        if repository is not None:
            os.environ["GIT_CONFIG_KEY_4"] = "safe.directory"
            os.environ["GIT_CONFIG_VALUE_4"] = repository.resolve().as_posix()
        try:
            yield
        finally:
            for key, value in previous.items():
                if value is None:
                    os.environ.pop(key, None)
                else:
                    os.environ[key] = value
