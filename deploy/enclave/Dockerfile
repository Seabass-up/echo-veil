FROM rust:1.96-bookworm@sha256:a339861ae23e9abb272cea45dfafde21760d2ce6577a70f8a926153677902663 AS zkp-builder
WORKDIR /build
COPY crates/echo-veil-zkp ./crates/echo-veil-zkp
RUN cargo build --release --locked --manifest-path crates/echo-veil-zkp/Cargo.toml

FROM ubuntu:24.04@sha256:4fbb8e6a8395de5a7550b33509421a2bafbc0aab6c06ba2cef9ebffbc7092d90
ENV DEBIAN_FRONTEND=noninteractive \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PYTHONPATH=/app/src
RUN apt-get update \
    && apt-get install -y --no-install-recommends python3 python3-pip libgomp1 ca-certificates \
    && rm -rf /var/lib/apt/lists/*
RUN groupadd --gid 10001 echo-veil \
    && useradd --uid 10001 --gid echo-veil --home-dir /nonexistent --shell /usr/sbin/nologin echo-veil \
    && install -d -o echo-veil -g echo-veil -m 0700 /var/lib/echo-veil/ckks
WORKDIR /app
COPY --chown=0:10001 --chmod=0440 pyproject.toml README.md LICENSE ./
COPY --chown=0:10001 src ./src
RUN find /app/src -type d -exec chmod 0550 {} + \
    && find /app/src -type f -exec chmod 0440 {} +
COPY deploy/enclave/requirements.lock deploy/enclave/openfhe.lock /tmp/requirements/
RUN python3 -m pip install --no-cache-dir --break-system-packages \
        --require-hashes -r /tmp/requirements/requirements.lock \
    && python3 -m pip install --no-cache-dir --break-system-packages \
        --require-hashes -r /tmp/requirements/openfhe.lock \
    && rm -rf /tmp/requirements
COPY --chown=0:10001 --chmod=0550 --from=zkp-builder \
    /build/crates/echo-veil-zkp/target/release/echo-veil-zkp \
    /usr/local/bin/echo-veil-zkp
USER 10001:10001
RUN python3 -c "import echo_veil, echo_veil_origin, openfhe"
EXPOSE 8080
ENTRYPOINT ["python3", "-m", "uvicorn"]
CMD ["echo_veil_origin.app:load_app", "--factory", "--host", "0.0.0.0", "--port", "8080", "--no-server-header"]
