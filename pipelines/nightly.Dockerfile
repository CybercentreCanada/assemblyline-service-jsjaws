FROM cccstemp.azurecr.io/assemblyline-root-build:stable AS base

# Install necessary packages for service testing
RUN apt-get update
RUN apt-get install -y libfuzzy-dev libfuzzy2 curl
RUN if [[ -f "$(pwd)/pkglist.txt" ]]; then
RUN   grep -vE '^#' "$(pwd)/pkglist.txt" | xargs apt install -y
RUN fi
RUN # Pinning to this version of Node
RUN export NODE_VERSION=19.7.0
RUN cd /usr/local
RUN curl https://nodejs.org/dist/v${NODE_VERSION}/node-v${NODE_VERSION}-linux-x64.tar.xz --output node-v${NODE_VERSION}-linux-x64.tar.xz
RUN [ ! -f node-v${NODE_VERSION}-linux-x64.tar.xz ] && echo "Node did not download properly" && exit
RUN tar -xJf node-v${NODE_VERSION}-linux-x64.tar.xz --strip 1
RUN cd $currdir
RUN node --version
RUN npm --version
RUN cd tools
RUN npm install --verbose
RUN cd ..
RUN rm -rf /var/lib/apt/lists/*
