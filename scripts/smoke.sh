#!/bin/sh
set -eu
root=$(cd "$(dirname "$0")/.." && pwd)
url=${ARTIFACT_HOST_URL:-http://127.0.0.1:18080}
admin=${ARTIFACT_HOST_ADMIN_TOKEN:-test-admin}
userjson=$(ARTIFACT_HOST_URL="$url" ARTIFACT_HOST_ADMIN_TOKEN="$admin" /tmp/ah user add smoke)
token=$(printf '%s' "$userjson" | python3 -c 'import sys,json; print(json.load(sys.stdin)["token"])')
pub=$(/tmp/ah publish --url "$url" --token "$token" --visibility public "$root/testdata/hello")
printf '%s\n' "$pub"
page_url=$(printf '%s' "$pub" | python3 -c 'import sys,json; print(json.load(sys.stdin)["url"])')
code=$(curl -sS -o /tmp/ah-page.html -w '%{http_code}' "$page_url")
echo "GET $page_url -> $code"
test "$code" = "200"
grep -q artifact-host /tmp/ah-page.html
priv=$(/tmp/ah publish --url "$url" --token "$token" --visibility owner "$root/testdata/hello")
priv_url=$(printf '%s' "$priv" | python3 -c 'import sys,json; print(json.load(sys.stdin)["url"])')
code=$(curl -sS -o /dev/null -w '%{http_code}' "$priv_url")
echo "GET owner anon $priv_url -> $code"
test "$code" = "401"
code=$(curl -sS -o /dev/null -w '%{http_code}' -H "Authorization: Bearer $token" "$priv_url")
echo "GET owner auth -> $code"
test "$code" = "200"
echo smoke_ok
