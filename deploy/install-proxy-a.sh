#!/bin/bash
# Run on proxy-a as ubuntu.
set -euo pipefail
ROOT=/opt/artifact-host
REPO=https://github.com/noomz/artifact-host.git

if [[ $(id -u) -eq 0 ]]; then
  echo "run as ubuntu, not root" >&2
  exit 2
fi

sudo mkdir -p "$ROOT/data"
sudo chown ubuntu:ubuntu "$ROOT"
sudo chown 65532:65532 "$ROOT/data"

if [[ -z "${INSTALL_SHA:-}" ]]; then
  echo "INSTALL_SHA is required (reviewed commit)" >&2
  exit 2
fi
if [[ ! -d "$ROOT/src/.git" ]]; then
  git clone "$REPO" "$ROOT/src"
fi
git -C "$ROOT/src" fetch origin
if ! git -C "$ROOT/src" cat-file -e "${INSTALL_SHA}^{commit}"; then
  echo "INSTALL_SHA $INSTALL_SHA not in $REPO" >&2
  exit 2
fi
git -C "$ROOT/src" checkout --detach "$INSTALL_SHA"

if [[ ! -f "$ROOT/.env" ]]; then
  token=$(python3 -c 'import secrets; print(secrets.token_hex(32))')
  umask 077
  cat > "$ROOT/.env" <<EOF
ARTIFACT_HOST_ADMIN_TOKEN=$token
AWS_ACCESS_KEY_ID=
AWS_SECRET_ACCESS_KEY=
EOF
  echo "wrote $ROOT/.env"
  grep '^ARTIFACT_HOST_ADMIN_TOKEN=' "$ROOT/.env"
fi

if ! grep -q '^AWS_ACCESS_KEY_ID=.\+' "$ROOT/.env"; then
  echo "edit $ROOT/.env and set AWS_ACCESS_KEY_ID / AWS_SECRET_ACCESS_KEY for bucket noomz-artifact-host, then re-run" >&2
  exit 2
fi

cp "$ROOT/.env" "$ROOT/src/deploy/.env"
sudo docker compose -f "$ROOT/src/deploy/docker-compose.yml" --project-directory "$ROOT/src/deploy" up -d --build

sudo cp "$ROOT/src/deploy/nginx-http.conf" /etc/nginx/sites-available/artifacts
sudo ln -sfn /etc/nginx/sites-available/artifacts /etc/nginx/sites-enabled/artifacts
sudo nginx -t
sudo systemctl reload nginx
sudo certbot --nginx -d artifacts.noomz.space --non-interactive --agree-tos --redirect --register-unsafely-without-email
curl -sfS https://artifacts.noomz.space/healthz
echo
echo "ok https://artifacts.noomz.space/healthz"
