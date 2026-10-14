# "Send with todoke" in Files (Nautilus), through nautilus-python. Local
# files and folders only; runs `todoke-desktop --send PATH...` without a
# shell. Nautilus 43+ (API 4.0) and older (API 3.0).

import subprocess
import sys

import gi

try:
    gi.require_version("Nautilus", "4.0")
except ValueError:
    gi.require_version("Nautilus", "3.0")

from gi.repository import GObject, Nautilus  # noqa: E402


class TodokeMenuProvider(GObject.GObject, Nautilus.MenuProvider):
    def get_file_items(self, *args):
        # Nautilus 4: (files); Nautilus 3: (window, files).
        files = args[-1]
        paths = []
        for item in files:
            if item.get_uri_scheme() != "file":
                return []
            location = item.get_location()
            path = location.get_path() if location is not None else None
            if not path:
                return []
            paths.append(path)
        if not paths:
            return []
        menu_item = Nautilus.MenuItem(
            name="TodokeMenuProvider::Send",
            label="Send with todoke",
            tip="Send the selection to a contact",
        )
        menu_item.connect("activate", self._send, paths)
        return [menu_item]

    @staticmethod
    def _send(_menu_item, paths):
        # Everything after --send is a path, even one starting with "-".
        try:
            subprocess.Popen(
                ["todoke-desktop", "--send", *paths],
                stdin=subprocess.DEVNULL,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                close_fds=True,
                start_new_session=True,
            )
        except OSError as error:
            print(f"todoke: cannot start todoke-desktop: {error}", file=sys.stderr)
