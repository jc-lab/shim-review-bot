FROM debian:bookworm-slim as builder

ENV DEBIAN_FRONTEND=noninteractive

RUN mkdir -p /work && \
    apt-get update -y && \
    apt-get install -y \
      ca-certificates openssl coreutils bash curl tar xz-utils bzip2 git sed diffutils patch make pesign \
      libelf-dev \
      binutils-x86-64-linux-gnu gcc \
      binutils-aarch64-linux-gnu gcc-aarch64-linux-gnu

ARG SHIM_ARCHIVE_URL=https://github.com/rhboot/shim/releases/download/15.7/shim-15.7.tar.bz2
ARG SHIM_ARCHIVE_FILE=shim-15.7.tar.bz2
ARG SHIM_ARCHIVE_SHA256=87cdeb190e5c7fe441769dde11a1b507ed7328e70a178cd9858c7ac7065cfade

COPY [ "vendor_cert.der", "sbat.csv", "vendor_dbx.bin", "/tmp/" ]
COPY [ "patches", "/tmp/patches" ]
RUN cd /tmp && \
    set -x  && \
    curl -L -o "/tmp/${SHIM_ARCHIVE_FILE}" "${SHIM_ARCHIVE_URL}" && \
    echo "${SHIM_ARCHIVE_SHA256} ${SHIM_ARCHIVE_FILE}" | sha256sum -c

WORKDIR /work

RUN mkdir -p /work/output && \
    dpkg -l | tee /work/output/builder-packages.txt

ARG EFIDIR=Test
RUN tar --strip-components=1 -xf "/tmp/${SHIM_ARCHIVE_FILE}" && \
    (for name in $(find /tmp/patches -type f -name "*.patch" | sort); do patch -p1 < $name; done) && \
    mkdir -p \
      build-x86_64/data \
      build-ia32/data \
      build-aarch64/data \
      output/x86_64 \
      output/ia32 \
      output/aarch64 && \
    cp -f /tmp/sbat.csv data/sbat.csv && \
    cp /tmp/sbat.csv build-x86_64/data/sbat.csv && \
    cp /tmp/sbat.csv build-ia32/data/sbat.csv && \
    cp /tmp/sbat.csv build-aarch64/data/sbat.csv

RUN make -C build-x86_64 TOPDIR=.. ARCH=x86_64 VENDOR_CERT_FILE=/tmp/vendor_cert.der VENDOR_DBX_FILE=/tmp/vendor_dbx.bin EFIDIR=${EFIDIR} DESTDIR=/work/output/x86_64 ENABLE_SHIM_HASH=true -f ../Makefile install
RUN make -C build-ia32 TOPDIR=.. ARCH=ia32 VENDOR_CERT_FILE=/tmp/vendor_cert.der VENDOR_DBX_FILE=/tmp/vendor_dbx.bin EFIDIR=${EFIDIR} DESTDIR=/work/output/ia32 ENABLE_SHIM_HASH=true -f ../Makefile install
RUN make -C build-aarch64 TOPDIR=.. ARCH=aarch64 CROSS_COMPILE=aarch64-linux-gnu- VENDOR_CERT_FILE=/tmp/vendor_cert.der VENDOR_DBX_FILE=/tmp/vendor_dbx.bin EFIDIR=${EFIDIR} DESTDIR=/work/output/aarch64 ENABLE_SHIM_HASH=true -f ../Makefile install

ARG NO_CACHE=""
RUN echo "${NO_CACHE}" > /dev/null && \
    echo "::review hash-start" && \
    for name in $(find /work/output/ -type f -name "shim*.efi"); do sha256sum $name; done && \
    echo "::review hash-end"
