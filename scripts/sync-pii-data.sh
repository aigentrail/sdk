#! /usr/bin/env nix-shell
#! nix-shell -i bash -p gh
# The monorepo's services/common/ruledsl owns the detector data; every SDK vendors byte-identical copies.
set -euo pipefail

if [ $# -ne 1 ]; then
  echo "usage: $0 <aigentrail monorepo commit>" >&2
  exit 2
fi
monorepo_ref="$1"

repo_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
fetch() {
  gh api -H "Accept: application/vnd.github.raw" \
    "repos/aigentrail/aigentrail/contents/services/common/ruledsl/$1?ref=$monorepo_ref"
}
fetch pii_conformance.json >"$repo_root/spec/pii_conformance.json"
for name in gitleaks_rules.json gitleaks_LICENSE iban_registry.json; do
  fetch "$name" >"$repo_root/go/$name"
  cp "$repo_root/go/$name" "$repo_root/python/gentrail/pii_data/$name"
  cp "$repo_root/go/$name" "$repo_root/js/gentrail-ai/data/$name"
done
