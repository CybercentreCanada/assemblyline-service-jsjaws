FROM cccstemp.azurecr.io/assemblyline-root-build:stable AS base

# Install necessary packages for service testing
RUN apt-get update
RUN apt-get install -y libfuzzy-dev libfuzzy2 curl

# Pinning to this version of Node
ENV NODE_VERSION=19.7.0
WORKDIR /usr/local
RUN curl https://nodejs.org/dist/v${NODE_VERSION}/node-v${NODE_VERSION}-linux-x64.tar.xz --output node-v${NODE_VERSION}-linux-x64.tar.xz
RUN tar -xJf node-v${NODE_VERSION}-linux-x64.tar.xz --strip 1
RUN node --version
RUN npm --version
COPY ./tools ./tools
WORKDIR tools
RUN npm install --verbose
RUN rm -rf /var/lib/apt/lists/*
