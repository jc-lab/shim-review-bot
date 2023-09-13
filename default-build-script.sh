#!/bin/sh

docker buildx build "--output=type=tar,dest=${BUILD_OUTPUT_FILE}" .
