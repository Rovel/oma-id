FROM archlinux@sha256:82b1b08faae9d61e3e7e13d562f4d09114d939105b0d59ff34140f3bd418593a

# A coherent Arch repository snapshot, never a partial rolling upgrade.
RUN echo 'Server = https://archive.archlinux.org/repos/2026/09/04/$repo/os/$arch' > /etc/pacman.d/mirrorlist
RUN pacman -Syu --noconfirm --needed base-devel rust cargo pam
COPY pam-test-client.c /src/pam-test-client.c
COPY context.tar.gz /tmp/context.tar.gz
RUN tar -xzf /tmp/context.tar.gz -C /src
COPY build.sh /build.sh
WORKDIR /src/native
CMD ["bash", "/build.sh"]
