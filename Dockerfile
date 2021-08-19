ARG branch=latest
FROM cccs/assemblyline-v4-service-base:$branch

ENV SERVICE_PATH jsjaws.JsJaws

# Get required apt packages
USER root
RUN apt-get update && apt-get install -y nodejs npm && rm -rf /var/lib/apt/lists/*

# Switch to assemblyline user
USER assemblyline

# Copy JsJaws service code
WORKDIR /opt/al_service
COPY ../assemblyline-service-jsjaws .

# Insall Malware Jail
WORKDIR ./assemblyline-service-jsjaws/malware-jail
RUN npm install

WORKDIR /opt/al_service

# Patch version in manifest
ARG version=4.0.0.dev1
USER root
RUN sed -i -e "s/\$SERVICE_TAG/$version/g" service_manifest.yml

# Switch to assemblyline user
USER assemblyline