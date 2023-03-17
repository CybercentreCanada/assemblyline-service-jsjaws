ARG branch=latest
FROM cccs/assemblyline-v4-service-base:$branch

ENV SERVICE_PATH jsjaws.JsJaws

# Get required apt packages
USER root
RUN apt-get update && apt-get install -y curl

# This route via the nodesource PPA works great, until the URI goes down...
# RUN curl -sL https://deb.nodesource.com/setup_19.x -o /tmp/nodesource_setup.sh && bash /tmp/nodesource_setup.sh && rm /tmp/nodesource_setup.sh
# RUN apt-get install -y nodejs && rm -rf /var/lib/apt/lists/*
# RUN node --version

# Switch to assemblyline user
USER assemblyline

ENV NVM_DIR /home/assemblyline/.nvm
ENV NODE_VERSION 19.1

# Here is the NVM alternative
SHELL ["/bin/bash", "--login", "-c"]
RUN curl -o- https://raw.githubusercontent.com/creationix/nvm/master/install.sh | bash
# Set back to default shell
SHELL ["/bin/sh", "-c"]
# We are going to pin this version
RUN nvm install $NODE_VERSION
# Set the correct paths
ENV NODE_PATH $NVM_DIR/v$NODE_VERSION/lib/node_modules
ENV PATH      $NVM_DIR/v$NODE_VERSION/bin:$PATH
# Node version as user
RUN node --version

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
