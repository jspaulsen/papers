#!/usr/bin/env bash

TAG="papers-tests"

DATABASE=false
RELEASE=""

POSITIONAL=()

while [[ $# -gt 0 ]]; do
  key="$1"

  case $key in
    --database)
      DATABASE=true
      shift # past argument
      ;;
    *)    # unknown option
      POSITIONAL+=("$1") # save it in an array for later
      shift # past argument
      ;;
  esac
done


source build.sh --target build --tag $TAG


if [ "$DATABASE" = true ]; then
    docker network create -d bridge papers_test_network

    docker-compose run \
        --rm \
        ${TAG} \
        cargo test --release -- --include-ignored

    ERR_CODE=$?

    docker-compose down
    docker network rm papers_test_network
    exit $ERR_CODE
else
    docker run $TAG cargo test --release
fi
