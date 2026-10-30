#!/bin/bash
# Run on your laptop from this repo (AWS CLI as noomz, SSH to proxy-a).
# Does not print secrets. Admin token lands only in /opt/artifact-host/.env on the host.
set -euo pipefail

HOST="${PROXY_A_SSH:-ubuntu@52.74.112.181}"
USER_NAME=artifact-host-proxy-a
BUCKET=noomz-artifact-host
POLICY_NAME=artifact-host-s3
REMOTE=/opt/artifact-host
HERE=$(cd "$(dirname "$0")" && pwd)
TMP=$(mktemp -d)
NEW_KEY_ID=""
cleanup() {
  rm -rf "$TMP"
  if [[ -n "${NEW_KEY_ID:-}" ]]; then
    aws iam delete-access-key --user-name "$USER_NAME" --access-key-id "$NEW_KEY_ID" >/dev/null 2>&1 || true
  fi
}
trap cleanup EXIT
chmod 700 "$TMP"

echo "1/5 IAM user $USER_NAME"
if aws iam get-user --user-name "$USER_NAME" >/dev/null 2>&1; then
  echo "    exists"
else
  aws iam create-user --user-name "$USER_NAME" >/dev/null
  echo "    created"
fi

aws iam put-user-policy \
  --user-name "$USER_NAME" \
  --policy-name "$POLICY_NAME" \
  --policy-document "{
    \"Version\": \"2012-10-17\",
    \"Statement\": [
      {
        \"Effect\": \"Allow\",
        \"Action\": [\"s3:ListBucket\", \"s3:GetBucketLocation\"],
        \"Resource\": \"arn:aws:s3:::$BUCKET\"
      },
      {
        \"Effect\": \"Allow\",
        \"Action\": [\"s3:GetObject\", \"s3:PutObject\", \"s3:DeleteObject\", \"s3:AbortMultipartUpload\"],
        \"Resource\": \"arn:aws:s3:::$BUCKET/*\"
      }
    ]
  }"
echo "    policy ok"

echo "2/5 host dir"
ssh -o BatchMode=yes "$HOST" "sudo mkdir -p $REMOTE && sudo chown ubuntu:ubuntu $REMOTE"

need_key=1
if ssh -o BatchMode=yes "$HOST" "test -f $REMOTE/.env"; then
  remote_len=$(ssh -o BatchMode=yes "$HOST" "awk -F= '/^AWS_ACCESS_KEY_ID=/{print length(\$2); exit}' $REMOTE/.env")
  if [[ "${remote_len:-0}" -gt 8 ]]; then
    need_key=0
    echo "    remote .env already has AWS_ACCESS_KEY_ID"
  fi
fi

echo "3/5 access key"
if [[ "$need_key" -eq 1 ]]; then
  aws iam create-access-key --user-name "$USER_NAME" --output json >"$TMP/key.json"
  python3 - "$TMP/key.json" "$TMP/ah.env" "$TMP/keyid" <<'PY'
import json, secrets, sys, os
src, dst, kid = sys.argv[1], sys.argv[2], sys.argv[3]
with open(src) as f:
    k = json.load(f)["AccessKey"]
token = secrets.token_hex(32)
body = (
    f"ARTIFACT_HOST_ADMIN_TOKEN={token}\n"
    f"AWS_ACCESS_KEY_ID={k['AccessKeyId']}\n"
    f"AWS_SECRET_ACCESS_KEY={k['SecretAccessKey']}\n"
)
fd = os.open(dst, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
os.write(fd, body.encode())
os.close(fd)
open(kid, "w").write(k["AccessKeyId"])
print("    AccessKeyId", k["AccessKeyId"])
PY
  rm -f "$TMP/key.json"
  NEW_KEY_ID=$(cat "$TMP/keyid")
  scp -o BatchMode=yes "$TMP/ah.env" "$HOST:$REMOTE/.env"
  ssh -o BatchMode=yes "$HOST" "chmod 600 $REMOTE/.env"
  echo "    wrote $REMOTE/.env"
  keep=$NEW_KEY_ID
  NEW_KEY_ID=""
  for k in $(aws iam list-access-keys --user-name "$USER_NAME" --query 'AccessKeyMetadata[].AccessKeyId' --output text); do
    if [[ "$k" != "$keep" ]]; then
      aws iam delete-access-key --user-name "$USER_NAME" --access-key-id "$k" || echo "warn: could not delete access key $k" >&2
    fi
  done
else
  echo "    skipped key create"
fi

echo "4/5 install on host"
SHA=$(git -C "$HERE/.." rev-parse HEAD)
scp -o BatchMode=yes "$HERE/install-proxy-a.sh" "$HOST:/tmp/ah-install.sh"
ssh -o BatchMode=yes "$HOST" "INSTALL_SHA=$SHA bash /tmp/ah-install.sh"

echo "5/5 check"
curl -sfS https://artifacts.noomz.space/healthz
echo
echo "done. admin token is on the host: ssh $HOST 'grep ARTIFACT_HOST_ADMIN_TOKEN $REMOTE/.env'"
echo "then: ARTIFACT_HOST_URL=https://artifacts.noomz.space ARTIFACT_HOST_ADMIN_TOKEN=... ah user add ada"
