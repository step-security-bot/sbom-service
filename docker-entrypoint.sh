#!/usr/bin/env bash

set -e

WORKSPACE=/opt/sbom-service

cd ${WORKSPACE}
set +e
git pull
git submodule update --recursive

set -e
/bin/bash start-sbom-service.sh
