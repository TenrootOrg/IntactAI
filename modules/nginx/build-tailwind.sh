#!/usr/bin/env bash
# Build the IntactAI dashboard's Tailwind stylesheet.
#
# Runs the Tailwind CLI inside a node:20-alpine container so there's no
# host-side Node/npm dependency. The output (html/css/tailwind.css) is
# committed to the repo — nginx serves it directly. Re-run this script
# whenever utility classes change (new file, new class names).
#
# Usage:
#   bash modules/nginx/build-tailwind.sh
set -euo pipefail

MODULE_DIR="$(cd "$(dirname "$0")" && pwd)"

docker run --rm \
    -v "${MODULE_DIR}:/work" \
    -w /work \
    node:20-alpine \
    sh -c 'npm install --no-fund --no-audit --silent tailwindcss@3 && \
           npx tailwindcss \
               -c tailwind.config.js \
               -i tailwind.input.css \
               -o html/css/tailwind.css \
               --minify'

echo "Tailwind stylesheet built: ${MODULE_DIR}/html/css/tailwind.css"
ls -lh "${MODULE_DIR}/html/css/tailwind.css"
