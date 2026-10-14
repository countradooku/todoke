# Packages prebuilt release binaries (build-rpm.sh): no build and no
# network here. build-rpm.sh defines todoke_version and todoke_release.
%{!?todoke_version:%{error:build with packaging/linux/build-rpm.sh}}

%global debug_package %{nil}
%global _build_id_links none
# The binaries are cargo's release builds, packaged as built; no
# byte-compiled copy of the Nautilus extension either.
%global __os_install_post %{nil}

Name:           todoke
Version:        %{todoke_version}
Release:        %{?todoke_release}%{!?todoke_release:1}
Summary:        End-to-end encrypted file transfer between your devices
License:        Apache-2.0 OR MIT
URL:            https://github.com/countradooku/todoke
Source0:        todoke-%{version}.tar
ExclusiveArch:  x86_64 aarch64

Requires:       hicolor-icon-theme
# Loaded at run time by the renderer (wgpu): Vulkan, or EGL for OpenGL ES.
Requires:       (vulkan-loader or mesa-libEGL)
Recommends:     nautilus-python
Recommends:     (gnome-keyring or kf6-kwallet)

%description
todoke sends files and folders between your phones and computers. Devices
pair once, and every transfer is end-to-end encrypted. This package holds
the desktop app (todoke-desktop), the command line (todoke), and "Send with
todoke" for Dolphin, Nemo, and Files (Nautilus, with nautilus-python).

%prep
%setup -q

%build
# Built by cargo before rpmbuild.

%install
install -Dm0755 todoke-desktop %{buildroot}%{_bindir}/todoke-desktop
install -Dm0755 todoke %{buildroot}%{_bindir}/todoke
install -Dm0644 linux/org.todoke.todoke.desktop %{buildroot}%{_datadir}/applications/org.todoke.todoke.desktop
install -Dm0644 linux/org.todoke.todoke.metainfo.xml %{buildroot}%{_datadir}/metainfo/org.todoke.todoke.metainfo.xml
for size in 16 24 32 48 64 128 256 512; do
    install -Dm0644 icons/todoke-${size}.png \
        %{buildroot}%{_datadir}/icons/hicolor/${size}x${size}/apps/org.todoke.todoke.png
done
install -Dm0644 icons/todoke.svg %{buildroot}%{_datadir}/icons/hicolor/scalable/apps/org.todoke.todoke.svg
install -Dm0644 linux/dolphin/org.todoke.todoke.desktop %{buildroot}%{_datadir}/kio/servicemenus/org.todoke.todoke.desktop
install -Dm0644 linux/nemo/todoke.nemo_action %{buildroot}%{_datadir}/nemo/actions/todoke.nemo_action
install -Dm0644 linux/nautilus/todoke.py %{buildroot}%{_datadir}/nautilus-python/extensions/todoke.py

%files
%license LICENSE-APACHE LICENSE-MIT
%{_bindir}/todoke-desktop
%{_bindir}/todoke
%{_datadir}/applications/org.todoke.todoke.desktop
%{_datadir}/metainfo/org.todoke.todoke.metainfo.xml
%{_datadir}/icons/hicolor/*/apps/org.todoke.todoke.*
# The file managers' directories, which none of todoke's dependencies own.
%dir %{_datadir}/kio
%dir %{_datadir}/kio/servicemenus
%{_datadir}/kio/servicemenus/org.todoke.todoke.desktop
%dir %{_datadir}/nemo
%dir %{_datadir}/nemo/actions
%{_datadir}/nemo/actions/todoke.nemo_action
%dir %{_datadir}/nautilus-python
%dir %{_datadir}/nautilus-python/extensions
%{_datadir}/nautilus-python/extensions/todoke.py
