ARG branch=latest
FROM cccs/assemblyline-v4-service-base:$branch

ENV SERVICE_PATH jsjaws.JsJaws

# Get required apt packages
USER root
RUN apt-get update && apt-get install -y curl

ENV NODE_VERSION 19.1.0
WORKDIR /usr/local
RUN curl https://nodejs.org/dist/v${NODE_VERSION}/node-v${NODE_VERSION}-linux-x64.tar.xz --output node-v${NODE_VERSION}-linux-x64.tar.xz
RUN tar xJf node-v${NODE_VERSION}-linux-x64.tar.xz --strip 1
RUN which node
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

USER assemblyline
WORKDIR /opt/al_service

# Patch version in manifest
ARG version=4.0.0.dev1
USER root
RUN sed -i -e "s/\$SERVICE_TAG/$version/g" service_manifest.yml

# Switch to assemblyline user
USER assemblyline
