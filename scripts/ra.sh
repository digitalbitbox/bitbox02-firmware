#!/usr/bin/env bash
DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" >/dev/null && pwd )"
PROJECT_NAME="$(basename "$(realpath "$DIR/..")")"
CONTAINER_NAME=$PROJECT_NAME-dev

exec docker exec --user=dockeruser --workdir="$DIR/.." -i "$CONTAINER_NAME" rust-analyzer
