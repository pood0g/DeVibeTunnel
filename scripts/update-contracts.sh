#!/usr/bin/env bash
# Copies regenerated Java contract classes from a microsoft/dev-tunnels checkout into this
# project. Only files generated from the C# contracts (those starting with a
# "// Generated from" comment) are copied; hand-written files such as TunnelContracts.java and
# the *Statics.java classes are never overwritten.
#
# Usage: scripts/update-contracts.sh <path-to-dev-tunnels-checkout>
# Run the C# build in that checkout first; see "Updating the contract classes" in README.md.
set -euo pipefail

if [ $# -ne 1 ]; then
  echo "Usage: $0 <path-to-dev-tunnels-checkout>" >&2
  exit 2
fi

contracts="src/main/java/com/microsoft/tunnels/contracts"
source_dir="$1/java/$contracts"
target_dir="$(cd "$(dirname "$0")/.." && pwd)/$contracts"

if [ ! -d "$source_dir" ]; then
  echo "Not a dev-tunnels checkout (missing $source_dir)." >&2
  exit 1
fi

is_generated() {
  head -n 5 "$1" | grep -q '^// Generated from '
}

copied=0
added=()
for file in "$source_dir"/*.java; do
  name="$(basename "$file")"
  is_generated "$file" || continue
  if [ -f "$target_dir/$name" ] && ! is_generated "$target_dir/$name"; then
    echo "Skipping $name: it is hand-written in this project." >&2
    continue
  fi
  [ -f "$target_dir/$name" ] || added+=("$name")
  cp "$file" "$target_dir/$name"
  copied=$((copied + 1))
done

removed=()
for file in "$target_dir"/*.java; do
  name="$(basename "$file")"
  if is_generated "$file" && [ ! -f "$source_dir/$name" ]; then
    removed+=("$name")
  fi
done

echo "Copied $copied generated contract classes into $contracts."
if [ ${#added[@]} -gt 0 ]; then
  echo "New contract classes: ${added[*]}"
fi
if [ ${#removed[@]} -gt 0 ]; then
  echo "No longer generated upstream (review, then delete if unused): ${removed[*]}"
fi
echo "Review the changes with 'git diff', then build and test with 'mvn package'."
