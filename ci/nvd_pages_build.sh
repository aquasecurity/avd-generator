#!/bin/bash
set -u

CONTENT_NVD_DIR="content-nvd"

for file in "$CONTENT_NVD_DIR"/*
do
  YEAR="${file##*/}"
  if [ "$YEAR" == "*" ]; then
    echo "$(pwd)/$CONTENT_NVD_DIR doesn't exist."
    exit 1
  else
    echo "Building NVD $YEAR pages"
    hugo --destination=docs -c "$CONTENT_NVD_DIR/$YEAR" ## build nvd pages by year
  fi
done