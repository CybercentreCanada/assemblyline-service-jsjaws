ARG branch=latest
FROM cccs/assemblyline-v4-service-base:$branch

ENV SERVICE_PATH jsjaws.JsJaws

# Get required apt packages
USER root
# We need to install xz-utils in the Dockerfile and not in the azure-tests.yaml pipeline
# because the tests run on an Ubuntu image whereas the service container is based on a
# Debian image.
RUN apt-get update && apt-get install -y curl xz-utils

WORKDIR /usr/local
# Pinning to this version of Node
ARG NODE_VERSION=19.7.0
RUN curl https://nodejs.org/dist/v${NODE_VERSION}/node-v${NODE_VERSION}-linux-x64.tar.xz --output node-v${NODE_VERSION}-linux-x64.tar.xz
RUN tar -xJf node-v${NODE_VERSION}-linux-x64.tar.xz --strip 1
RUN node --version

# Switch to assemblyline user
USER assemblyline

WORKDIR /opt/al_service

# Install python dependencies
COPY requirements.txt requirements.txt
RUN pip install --no-cache-dir --user --requirement requirements.txt && rm -rf ~/.cache/pip

# Copy JsJaws service code
WORKDIR /opt/al_service
COPY . .

# Install Tools
USER root
WORKDIR ./tools
RUN npm install
RUN chown -R root:root node_modules

USER assemblyline
WORKDIR /opt/al_service

# Patch version in manifest
ARG version=4.0.0.dev1
USER root
RUN sed -i -e "s/\$SERVICE_TAG/$version/g" service_manifest.yml

# Switch to assemblyline user
USER assemblyline
