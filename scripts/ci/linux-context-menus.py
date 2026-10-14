"""Runs the installed file-manager items the way the file managers do:
the Exec lines of the Dolphin service menu and the Nemo action (with %F
replaced by a file), and the Nautilus extension's menu item (with stand-ins
for the gi modules Nautilus provides). Each must end with the running
window receiving the file (the caller checks TODOKE_HANDOFF_LOG).

Usage: python3 -I linux-context-menus.py FILE
"""

import configparser
import importlib.util
import shlex
import subprocess
import sys
import time
import types

DOLPHIN = "/usr/share/kio/servicemenus/org.todoke.todoke.desktop"
NEMO = "/usr/share/nemo/actions/todoke.nemo_action"
NAUTILUS = "/usr/share/nautilus-python/extensions/todoke.py"


def exec_line(path, section):
    parser = configparser.ConfigParser(interpolation=None)
    parser.optionxform = str
    parser.read(path, encoding="utf-8")
    return parser[section]["Exec"]


def run(argv):
    # A second launch hands its request over and exits 0.
    completed = subprocess.run(argv, timeout=30, check=False)
    if completed.returncode != 0:
        sys.exit(f"{argv} exited with {completed.returncode}")


def file_manager_exec(path, section, file):
    words = shlex.split(exec_line(path, section))
    return [file if word == "%F" else word for word in words]


def nautilus(file):
    """Loads the extension with minimal gi stand-ins and activates it."""
    started = []

    class GObject:
        pass

    class MenuProvider:
        pass

    class MenuItem:
        def __init__(self, **properties):
            self.properties = properties
            self.handlers = []

        def connect(self, signal, handler, *data):
            assert signal == "activate"
            self.handlers.append((handler, data))

        def activate(self):
            for handler, data in self.handlers:
                handler(self, *data)

    class Location:
        def get_path(self):
            return file

    class FileInfo:
        def get_uri_scheme(self):
            return "file"

        def get_location(self):
            return Location()

    gi = types.ModuleType("gi")
    gi.require_version = lambda name, version: None
    repository = types.ModuleType("gi.repository")
    repository.GObject = types.SimpleNamespace(GObject=GObject)
    repository.Nautilus = types.SimpleNamespace(MenuProvider=MenuProvider, MenuItem=MenuItem)
    gi.repository = repository
    sys.modules["gi"] = gi
    sys.modules["gi.repository"] = repository

    real_popen = subprocess.Popen

    def popen(argv, **options):
        process = real_popen(argv, **options)
        started.append(process)
        return process

    subprocess.Popen = popen
    spec = importlib.util.spec_from_file_location("todoke_nautilus", NAUTILUS)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    items = module.TodokeMenuProvider().get_file_items([FileInfo()])
    assert len(items) == 1 and items[0].properties["label"] == "Send with todoke", items
    items[0].activate()
    subprocess.Popen = real_popen
    assert len(started) == 1, started
    deadline = time.monotonic() + 30
    while started[0].poll() is None and time.monotonic() < deadline:
        time.sleep(0.2)
    if started[0].returncode != 0:
        sys.exit(f"the Nautilus item's launch ended with {started[0].returncode}")


def main():
    file = sys.argv[1]
    run(file_manager_exec(DOLPHIN, "Desktop Action send", file))
    run(file_manager_exec(NEMO, "Nemo Action", file))
    nautilus(file)
    print("Dolphin, Nemo, and Nautilus handed", file, "over")


main()
