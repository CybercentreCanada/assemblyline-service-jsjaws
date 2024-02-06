FROM cccstemp.azurecr.io/assemblyline-root-build:stable AS base

# Install necessary packages for service testing
RUN apt-get update
RUN apt-get install -y libfuzzy-dev libfuzzy2 curl wget unzip

# Pinning to this version of Node
ENV NODE_VERSION=19.7.0
WORKDIR /usr/local

# Download and install node
RUN curl https://nodejs.org/dist/v${NODE_VERSION}/node-v${NODE_VERSION}-linux-x64.tar.xz --output node-v${NODE_VERSION}-linux-x64.tar.xz
RUN tar -xJf node-v${NODE_VERSION}-linux-x64.tar.xz --strip 1

RUN echo "Installing Box-JS"
RUN mkdir /opt/al_support/
RUN wget https://github.com/cccs-kevin/box-js/archive/refs/heads/master.zip -O /opt/al_support/box-js.zip
RUN unzip /opt/al_support/box-js.zip -d /opt/al_support/box-js

# Check the version of node and npm, just to be sure
RUN node --version
RUN npm --version

# Cleanup
RUN rm -rf /var/lib/apt/lists/*
