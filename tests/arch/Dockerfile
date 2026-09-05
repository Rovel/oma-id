FROM archlinux@sha256:82b1b08faae9d61e3e7e13d562f4d09114d939105b0d59ff34140f3bd418593a

# A coherent Arch repository snapshot, never a partial rolling upgrade.
RUN echo 'Server = https://archive.archlinux.org/repos/2026/09/04/$repo/os/$arch' > /etc/pacman.d/mirrorlist
RUN pacman -Syu --noconfirm --needed base-devel go rust protobuf glib2 pam libpwquality libfido2 dbus git python
COPY authd.tar.gz /tmp/authd.tar.gz
RUN mkdir /src /out && tar -xzf /tmp/authd.tar.gz -C /src --strip-components=1
COPY build.sh /build.sh
WORKDIR /src
ENV GOTOOLCHAIN=go1.26.7
CMD ["bash", "/build.sh"]
