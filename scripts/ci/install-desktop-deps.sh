#!/usr/bin/env bash
# System libraries the desktop app (GPUI through gpui-kit) builds against on
# Linux: keyboard maps (xkbcommon), Wayland and X11 clients, and fonts
# (fontconfig, FreeType). Checked on Ubuntu 24.04; only these runners need
# it, and it does nothing elsewhere.
set -euo pipefail

if [[ "$(uname -s)" != Linux ]]; then
    exit 0
fi
sudo apt-get update -qq
sudo apt-get install -y -qq --no-install-recommends \
    libfontconfig-dev \
    libfreetype-dev \
    libwayland-dev \
    libx11-xcb-dev \
    libxcb1-dev \
    libxkbcommon-dev \
    libxkbcommon-x11-dev
