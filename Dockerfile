# syntax=docker/dockerfile:1
FROM python:3.12-slim-bookworm AS builder
ARG TARGETARCH
ENV PIP_DISABLE_PIP_VERSION_CHECK=1 PIP_NO_CACHE_DIR=1
WORKDIR /build

# The official npm package is read only for its pinned manifest and license.
# Install the same native release binary, never npm's auto-download launcher.
COPY scripts/install_lark_cli.py /build/install_lark_cli.py
RUN python /build/install_lark_cli.py --arch "${TARGETARCH}" --output /opt/lark-cli

COPY pyproject.toml requirements-lock.txt /build/
COPY dot2feishu/*.py /build/dot2feishu/
RUN python -m venv /opt/venv \
    && /opt/venv/bin/python -m pip install --no-deps -r requirements-lock.txt \
    && /opt/venv/bin/python -m pip install --no-deps . \
    && /opt/venv/bin/python -m pip check

FROM python:3.12-slim-bookworm AS runtime
ENV PATH="/opt/venv/bin:/usr/local/bin:/usr/bin:/bin" \
    HOME=/data \
    LARKSUITE_CLI_CONFIG_DIR=/data/config \
    LARKSUITE_CLI_DATA_DIR=/data/data \
    PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    TZ=UTC
RUN groupadd --gid 10001 bridge \
    && useradd --uid 10001 --gid 10001 --home-dir /data --no-create-home --shell /usr/sbin/nologin bridge \
    && install -d -m 0700 -o 10001 -g 10001 /data /data/config /data/data \
    && install -d -m 0755 /usr/local/share/dot2feishu
COPY --from=builder /opt/venv /opt/venv
COPY --from=builder --chmod=0555 /opt/lark-cli/lark-cli /usr/local/bin/lark-cli
COPY --from=builder /opt/lark-cli/lark-cli.sha256 /opt/lark-cli/lark-cli-LICENSE /opt/lark-cli/lark-cli-version /usr/local/share/dot2feishu/
RUN sha256sum --check /usr/local/share/dot2feishu/lark-cli.sha256
WORKDIR /data
USER 10001:10001
EXPOSE 8765
STOPSIGNAL SIGTERM
ENTRYPOINT ["python", "-m", "dot2feishu", "--root", "/data"]
CMD ["serve"]
