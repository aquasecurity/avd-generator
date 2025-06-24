#!/bin/bash
set -u

CONTENT_NVD_DIR="content-nvd"

## hugo overwrites searchindex.json files after each run.
## Create all-searchindex.json to combine all indexes from searchindex.json files into this file.
touch all-searchindex.json

for file in "$CONTENT_NVD_DIR"/*
do
  YEAR="${file##*/}"
  if [ "$YEAR" == "*" ]; then
    echo "$(pwd)/$CONTENT_NVD_DIR doesn't exist."
    exit 1
  else
    printf "\n===Building NVD $YEAR pages===\n"
    hugo --destination=docs -c "$CONTENT_NVD_DIR/$YEAR" ## build nvd pages by year
    ## merge all nvd indexes to all-searchindex.json file
    jq -sc '.[0] + .[1]' all-searchindex.json docs/searchindex.json > all-searchindex.tmp && mv all-searchindex.tmp all-searchindex.json
  fi
done

## build `compliance`, `misconfig`, and `nvd/index.md` pages
printf "\n===Building the remaining content===\n"
hugo --destination=docs

## merge nvd and other indexes to docs/searchindex.json
jq -sc '.[0] + .[1]' all-searchindex.json docs/searchindex.json > all-searchindex.tmp && mv all-searchindex.tmp docs/searchindex.json
