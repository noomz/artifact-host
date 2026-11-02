#!/bin/bash
# Run on your laptop from this repo (AWS CLI as noomz, SSH to proxy-a).
# Sets up the content-host wildcard cert and DNS. Safe to re-run. Prints no secrets.
#
# The certbot key lives in root's AWS config on the host, not in the app's .env,
# so the app container cannot change DNS. The policy allows only the one TXT
# record DNS-01 needs.
set -euo pipefail

HOST="${PROXY_A_SSH:-ubuntu@52.74.112.181}"
HOST_IP="${HOST#*@}"
USER_NAME=artifact-host-certbot
POLICY_NAME=certbot-dns-01
ZONE_NAME=noomz.space
CONTENT_DOMAIN=u.artifacts.noomz.space
CHALLENGE="_acme-challenge.$CONTENT_DOMAIN"
WILDCARD="*.$CONTENT_DOMAIN"

NEW_KEY_ID=""
cleanup() {
  if [[ -n "$NEW_KEY_ID" ]]; then
    aws iam delete-access-key --user-name "$USER_NAME" --access-key-id "$NEW_KEY_ID" >/dev/null 2>&1 || true
  fi
}
trap cleanup EXIT

ZONE_ID=$(aws route53 list-hosted-zones-by-name --dns-name "$ZONE_NAME" --max-items 1 \
  --query "HostedZones[?Name=='$ZONE_NAME.'].Id | [0]" --output text)
ZONE_ID=${ZONE_ID#/hostedzone/}
if [[ -z "$ZONE_ID" || "$ZONE_ID" == "None" ]]; then
  echo "hosted zone $ZONE_NAME not found" >&2
  exit 2
fi

echo "1/6 IAM user $USER_NAME"
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
        \"Action\": [\"route53:ListHostedZones\", \"route53:GetChange\"],
        \"Resource\": \"*\"
      },
      {
        \"Effect\": \"Allow\",
        \"Action\": \"route53:ChangeResourceRecordSets\",
        \"Resource\": \"arn:aws:route53:::hostedzone/$ZONE_ID\",
        \"Condition\": {
          \"ForAllValues:StringEquals\": {
            \"route53:ChangeResourceRecordSetsNormalizedRecordNames\": [\"$CHALLENGE\"],
            \"route53:ChangeResourceRecordSetsRecordTypes\": [\"TXT\"]
          }
        }
      }
    ]
  }"
echo "    policy ok"

echo "2/6 access key"
if ssh -o BatchMode=yes "$HOST" "sudo test -s /root/.aws/credentials"; then
  echo "    host already has /root/.aws/credentials"
else
  read -r NEW_KEY_ID secret < <(aws iam create-access-key --user-name "$USER_NAME" \
    --query 'AccessKey.[AccessKeyId,SecretAccessKey]' --output text)
  printf '[default]\naws_access_key_id=%s\naws_secret_access_key=%s\n' "$NEW_KEY_ID" "$secret" |
    ssh -o BatchMode=yes "$HOST" 'sudo install -d -m 700 /root/.aws && sudo sh -c "umask 077; cat > /root/.aws/credentials"'
  unset secret
  keep=$NEW_KEY_ID
  NEW_KEY_ID=""
  for k in $(aws iam list-access-keys --user-name "$USER_NAME" --query 'AccessKeyMetadata[].AccessKeyId' --output text); do
    if [[ "$k" != "$keep" ]]; then
      aws iam delete-access-key --user-name "$USER_NAME" --access-key-id "$k" || echo "warn: could not delete access key $k" >&2
    fi
  done
  echo "    wrote /root/.aws/credentials, key id $keep"
fi

echo "3/6 certbot route53 plugin"
ssh -o BatchMode=yes "$HOST" "sudo apt-get install -y -qq python3-certbot-dns-route53 >/dev/null"
echo "    ok"

CERTBOT="sudo certbot certonly --dns-route53 --cert-name $CONTENT_DOMAIN -d '$WILDCARD' --non-interactive --agree-tos --register-unsafely-without-email"

echo "4/6 dry run against Let's Encrypt staging"
# A new IAM key can take a short while to work.
for attempt in 1 2 3 4 5; do
  if ssh -o BatchMode=yes "$HOST" "$CERTBOT --dry-run"; then
    break
  fi
  if [[ "$attempt" -eq 5 ]]; then
    echo "dry run failed" >&2
    exit 1
  fi
  echo "    retry in 20s"
  sleep 20
done

echo "5/6 certificate"
# The hook is stored in the renewal config. Renewals through this plugin do not
# reload nginx by themselves.
ssh -o BatchMode=yes "$HOST" "$CERTBOT --keep-until-expiring --deploy-hook 'systemctl reload nginx'"

echo "6/6 wildcard DNS"
aws route53 change-resource-record-sets --hosted-zone-id "$ZONE_ID" --change-batch "{
  \"Changes\": [{
    \"Action\": \"UPSERT\",
    \"ResourceRecordSet\": {
      \"Name\": \"$WILDCARD\",
      \"Type\": \"A\",
      \"TTL\": 300,
      \"ResourceRecords\": [{\"Value\": \"$HOST_IP\"}]
    }
  }]
}" >/dev/null
echo "    $WILDCARD A $HOST_IP"
