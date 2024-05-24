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
    printf "\n===Building NVD $YEAR pages===\n"
    hugo --destination=docs -c "$CONTENT_NVD_DIR/$YEAR" ## build nvd pages by year
  fi
done

## build `compliance`, `misconfig`, `tracee` and `nvd/index.md` pages
printf "\n===Building the remaining content===\n"
hugo --destination=docs