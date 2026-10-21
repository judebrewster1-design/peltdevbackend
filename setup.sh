#!/usr/bin/env bash
# One-shot setup for a fresh Ubuntu 24.04 DigitalOcean droplet. Run as root
# from inside the unzipped folder:   bash deploy/setup.sh
set -euo pipefail
[ "$(id -u)" = 0 ] || { echo "Run as root (sudo -i)"; exit 1; }
SRC="$(cd "$(dirname "$0")/.." && pwd)"
APP=/opt/peltdev

echo "==> Packages"
export DEBIAN_FRONTEND=noninteractive
apt-get update -y
apt-get install -y python3 python3-venv python3-pip sqlite3 ufw unattended-upgrades curl

echo "==> App user + files"
id peltdev >/dev/null 2>&1 || useradd --system --create-home --home-dir "$APP" --shell /usr/sbin/nologin peltdev
mkdir -p "$APP/backend" "$APP/frontend/static/uploads"
cp "$SRC"/backend/*.py "$SRC"/backend/requirements.txt "$APP/backend/"
if [ ! -f "$APP/.env" ]; then
  cp "$SRC/.env.example" "$APP/.env"
  SK=$(python3 -c "import secrets;print(secrets.token_urlsafe(48))")
  sed -i "s|^FLASK_SECRET_KEY=.*|FLASK_SECRET_KEY=$SK|" "$APP/.env"
  sed -i "s|^FRONTEND_ORIGIN=.*||" "$APP/.env"
  echo "FRONTEND_ORIGIN=https://www.peltdev.com,https://peltdev.com" >> "$APP/.env"
  echo "==> Created $APP/.env with a fresh secret key. YOU must still edit it (nano $APP/.env)."
fi

echo "==> Python environment"
python3 -m venv "$APP/venv"
"$APP/venv/bin/pip" install --upgrade pip
"$APP/venv/bin/pip" install -r "$APP/backend/requirements.txt"

chown -R peltdev:peltdev "$APP"
chmod 600 "$APP/.env"

echo "==> Service"
cp "$SRC/deploy/peltdev.service" /etc/systemd/system/peltdev.service
systemctl daemon-reload
systemctl enable peltdev

echo "==> Nightly backups"
install -m 755 "$SRC/deploy/backup.sh" /usr/local/bin/peltdev-backup
echo "17 3 * * * root /usr/local/bin/peltdev-backup" > /etc/cron.d/peltdev-backup

echo "==> Firewall (SSH only; the web is reached through Cloudflare Tunnel, no open web ports)"
ufw default deny incoming
ufw default allow outgoing
ufw allow OpenSSH
ufw --force enable

echo "==> cloudflared"
curl -fsSL https://pkg.cloudflare.com/cloudflare-main.gpg -o /usr/share/keyrings/cloudflare-main.gpg
echo "deb [signed-by=/usr/share/keyrings/cloudflare-main.gpg] https://pkg.cloudflare.com/cloudflared any main" > /etc/apt/sources.list.d/cloudflared.list
apt-get update -y && apt-get install -y cloudflared

cat <<MSG

Done. Next:
  1) nano $APP/.env        (set OWNER_PASSWORD, platform e-Transfer/PayPal, etc.)
  2) systemctl start peltdev && curl -s localhost:8000/api/meta | head -c 100
  3) cloudflared service install <YOUR TUNNEL TOKEN>   (see deploy/DEPLOY.md)
MSG
