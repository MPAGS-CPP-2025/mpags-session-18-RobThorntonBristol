# See here for image contents: https://github.com/microsoft/vscode-dev-containers/tree/v0.134.1/containers/cpp/.devcontainer/base.Dockerfile
ARG VARIANT="bookworm"
FROM mcr.microsoft.com/devcontainers/cpp:1-${VARIANT}

# Install additional packages
RUN apt-get update && export DEBIAN_FRONTEND=noninteractive \
     && apt-get -y install --no-install-recommends doxygen graphviz tree clang-format

# Ensure .ssh directory is owned by vscode user
RUN mkdir -p ~vscode/.ssh && chown vscode ~vscode/.ssh
