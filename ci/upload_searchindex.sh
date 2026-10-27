#!/bin/bash
## Uploads the search index to MeiliSearch in chunks,
## so that no request exceeds the request size limits.
set -euo pipefail

INDEX_FILE="${1:?usage: $0 <searchindex.json>}"
: "${MEILI_HOST:?MEILI_HOST is not set}"
: "${MEILI_API_KEY:?MEILI_API_KEY is not set}"
CHUNK_SIZE="${CHUNK_SIZE:-25000}"
WAIT_TIMEOUT="${WAIT_TIMEOUT:-3600}"
POLL_INTERVAL="${POLL_INTERVAL:-10}"
MAX_POLL_FAILURES="${MAX_POLL_FAILURES:-5}"

CHUNK_DIR=$(mktemp -d)
trap 'rm -rf "$CHUNK_DIR"' EXIT

warn() {
  echo "::warning::$*" >&2
}

fail() {
  echo "::error::$*" >&2
  exit 1
}

split_index() {
  jq -c --argjson n "$CHUNK_SIZE" 'range(0; length; $n) as $i | .[$i:$i+$n]' "$INDEX_FILE" \
    | split -l 1 -a 4 - "$CHUNK_DIR/chunk_"

  shopt -s nullglob
  chunks=("$CHUNK_DIR"/chunk_*)
  if [ ${#chunks[@]} -eq 0 ]; then
    fail "$INDEX_FILE has no documents"
  fi
}

upload_chunks() {
  local i chunk info response update_id
  echo "Uploading $(jq length "$INDEX_FILE") documents in ${#chunks[@]} chunks of up to $CHUNK_SIZE"

  update_ids=()
  for i in "${!chunks[@]}"; do
    chunk=${chunks[$i]}
    info="chunk $((i + 1))/${#chunks[@]}: $(jq length "$chunk") documents, $(wc -c < "$chunk" | tr -d ' ') bytes"
    if ! response=$(curl --fail-with-body -sS \
      --connect-timeout 10 --max-time 300 \
      -H 'Content-Type: application/json' \
      -H "X-Meili-API-Key: $MEILI_API_KEY" \
      -X POST "$MEILI_HOST/indexes/avd/documents?primaryKey=title" \
      --data-binary @"$chunk"); then
      fail "$info, upload failed: $response"
    fi
    echo "$info, response: $response"

    update_id=$(jq -r '.updateId // empty' <<< "$response")
    if [ -z "$update_id" ]; then
      fail "no updateId in the response for chunk $((i + 1))"
    fi
    update_ids+=("$update_id")
  done
}

## MeiliSearch accepts documents into a queue and indexes them later,
## so a successful upload does not mean the documents were indexed.
wait_for_updates() {
  local deadline id update status failures=0
  deadline=$((SECONDS + WAIT_TIMEOUT))
  for id in "${update_ids[@]}"; do
    while true; do
      if update=$(curl --fail-with-body -sS \
        --connect-timeout 10 --max-time 30 \
        -H "X-Meili-API-Key: $MEILI_API_KEY" \
        "$MEILI_HOST/indexes/avd/updates/$id"); then
        failures=0
        status=$(jq -r '.status' <<< "$update")
      else
        failures=$((failures + 1))
        status="unknown"
        if [ "$failures" -ge "$MAX_POLL_FAILURES" ]; then
          fail "failed to get update $id $failures times in a row: $update"
        fi
        warn "failed to get update $id (attempt $failures/$MAX_POLL_FAILURES): $update"
      fi

      case "$status" in
        processed)
          echo "update $id processed"
          break
          ;;
        failed)
          fail "update $id failed: $update"
          ;;
        unknown)
          ## the status request failed, try again after the pause
          ;;
      esac

      if [ $SECONDS -ge $deadline ]; then
        fail "update $id is still $status after ${WAIT_TIMEOUT}s"
      fi
      sleep "$POLL_INTERVAL"
    done
  done
}

split_index
upload_chunks
wait_for_updates
