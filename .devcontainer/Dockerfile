FROM mcr.microsoft.com/devcontainers/base:ubuntu-24.04

ARG PYTHON_VERSIONS="3.8 3.9 3.10 3.11 3.12 3.13"
ENV PYENV_ROOT=/usr/local/pyenv
# Ensure uv (installed into /usr/local/bin) and pyenv shims are ahead of the base PATH.
ENV PATH="/usr/local/bin:${PYENV_ROOT}/bin:${PYENV_ROOT}/shims:${PATH}"

RUN apt-get update \
 && DEBIAN_FRONTEND=noninteractive apt-get install -y \
    build-essential curl git ca-certificates \
    libssl-dev zlib1g-dev libbz2-dev libreadline-dev libsqlite3-dev \
    libncursesw5-dev xz-utils tk-dev libxml2-dev libxmlsec1-dev pkg-config libxmlsec1-openssl \
    libffi-dev liblzma-dev \
 && rm -rf /var/lib/apt/lists/*

ENV UV_INSTALL_DIR=/usr/local/bin

RUN curl -fsSL https://pyenv.run | bash \
 && for v in $PYTHON_VERSIONS; do pyenv install "$v"; done \
 && pyenv global 3.13 \
 && pip install --no-cache-dir --upgrade pip \
 && curl -LsSf https://astral.sh/uv/install.sh | sh \
 && chown -R vscode:vscode "$PYENV_ROOT"
