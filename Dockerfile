FROM python:3.9-slim AS builder

RUN apt-get update && apt-get install -y \
    build-essential \
    libffi-dev \
    libssl-dev \
    cargo \
    && rm -rf /var/lib/apt/lists/*

COPY . /opt/pwncat

RUN python -m pip install -U pip setuptools wheel setuptools_rust
RUN cd /opt/pwncat && pip install .

FROM python:3.9-slim AS final

RUN apt-get update && apt-get install -y \
    libstdc++6 \
    && rm -rf /var/lib/apt/lists/* \
    && mkdir /work

COPY --from=builder /usr/local /usr/local

# Pre-download plugins in the final image. They land in ~/.local/share/pwncat,
# which the /usr/local copy above does not include, so this must run here
# rather than in the builder stage.
RUN pwncat-vl --download-plugins

WORKDIR /work

ENTRYPOINT ["pwncat-vl"]
