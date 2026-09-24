#! /usr/bin/env nix-shell
#! nix-shell -i bash -p gh
# The monorepo's services/common/ruledsl owns the detector data; both SDKs vendor byte-identical copies.
set -euo pipefail

if [ $# -ne 1 ]; then
  echo "usage: $0 <aigentrail monorepo commit>" >&2
  exit 2
fi
monorepo_ref="$1"

repo_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
for name in gitleaks_rules.json gitleaks_LICENSE iban_registry.json pii_conformance.json; do
  gh api -H "Accept: application/vnd.github.raw" \
    "repos/aigentrail/aigentrail/contents/services/common/ruledsl/$name?ref=$monorepo_ref" >"$repo_root/go/$name"
done
for name in gitleaks_rules.json gitleaks_LICENSE iban_registry.json; do
  cp "$repo_root/go/$name" "$repo_root/python/gentrail/pii_data/$name"
done
cp "$repo_root/go/pii_conformance.json" "$repo_root/python/tests/pii_conformance.json"
