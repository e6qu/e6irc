# Solanum built from source at a pinned ref (the ircd Libera runs).
# Provenance: https://github.com/solanum-ircd/solanum, ref below.
FROM debian:bullseye-slim AS build
# Pinned to a specific commit for a reproducible reference oracle.
# https://github.com/solanum-ircd/solanum/commit/48db98ab2b4191ba75047a74c79a353e4f82bf5a (2026-07-15)
ARG SOLANUM_REF=48db98ab2b4191ba75047a74c79a353e4f82bf5a
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential automake autoconf libtool libltdl-dev pkg-config \
    libsqlite3-dev flex bison git ca-certificates \
    && rm -rf /var/lib/apt/lists/*
RUN git clone https://github.com/solanum-ircd/solanum /src \
    && cd /src && git checkout "$SOLANUM_REF" \
    && ./autogen.sh \
    && ./configure --prefix=/opt/solanum --enable-epoll=no \
    && make -j"$(nproc)" && make install

FROM debian:bullseye-slim
RUN apt-get update && apt-get install -y --no-install-recommends \
    libsqlite3-0 libltdl7 && rm -rf /var/lib/apt/lists/*
# Solanum refuses to run as root.
RUN useradd -r -u 10000 solanum
COPY --from=build /opt/solanum /opt/solanum
COPY ircd.conf /opt/solanum/etc/ircd.conf
RUN chown -R solanum /opt/solanum
USER solanum
EXPOSE 6667
CMD ["/opt/solanum/bin/solanum", "-foreground"]
