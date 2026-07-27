#!/usr/bin/env bash
# Assemble the public site into site/dist/.
#
# The explainer pages sit at the root, so /journey.html keeps the paths they
# already link to each other by. The browser demo joins them as /demo.html
# with its assets alongside.
set -euo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
root="$(cd "$here/.." && pwd)"
dist="$here/dist"

"$root/demo/build.sh"

# An explainer page named like one of the demo's own files would be clobbered
# by the copies below without a word.
for reserved in demo.html main.js style.css; do
  if [ -e "$root/explainers/$reserved" ]; then
    echo "explainers/$reserved collides with a demo asset" >&2
    exit 1
  fi
done

rm -rf "$dist"
mkdir -p "$dist/vendor"

cp "$root"/explainers/*.html "$dist/"
cp "$root/demo/index.html" "$dist/demo.html"
cp "$root/demo/main.js" "$root/demo/style.css" "$dist/"
# The .d.ts files wasm-bindgen emits alongside these are build-time only.
cp "$root/demo/vendor/hyperscale_demo.js" \
   "$root/demo/vendor/hyperscale_demo_bg.wasm" "$dist/vendor/"

printf 'site assembled at %s (%s files, %s)\n' "$dist" \
  "$(find "$dist" -type f | wc -l | tr -d ' ')" \
  "$(du -sh "$dist" | cut -f1)"
