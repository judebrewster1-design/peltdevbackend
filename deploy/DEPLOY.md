# Deploying to DigitalOcean (about 20 minutes)

You need: a DigitalOcean account, your domain on Cloudflare, and this folder.

## 1. Create the droplet
- Create > Droplets > **Toronto (TOR1)** > **Ubuntu 24.04** > Basic > Regular > the
  cheapest size (1 GB RAM is plenty).
- Authentication: **SSH key** (recommended) or a password. Enable **Backups** (+20%) if you want.
- Name it `peltdev`. Create. Copy its IP.

## 2. Upload this folder and run setup
On your computer (Windows PowerShell works too), from the folder that contains `peltdev-backend`:
```
scp -r peltdev-backend root@YOUR_DROPLET_IP:/root/
ssh root@YOUR_DROPLET_IP
cd /root/peltdev-backend
bash deploy/setup.sh
```

## 3. Fill in the settings
```
nano /opt/peltdev/.env
```
Set at least: `OWNER_PASSWORD` (long and unguessable), `PLATFORM_ETRANSFER_EMAIL` and/or
`PLATFORM_PAYPAL_ME`, the `PLATFORM_IMAP_*` lines for automatic payment checking,
`ROOT_DOMAIN=peltdev.com`, `FLASK_ENV=production`. Leave `FRONTEND_ORIGIN` as set.
Never share this file.

Start it and check it:
```
systemctl start peltdev
curl -s localhost:8000/api/meta | head -c 120
journalctl -u peltdev -n 30 --no-pager
```

## 4. Connect it to api.peltdev.com (Cloudflare Tunnel)
1. Cloudflare dashboard > **Zero Trust** > Networks > **Tunnels** > Create a tunnel > Cloudflared.
2. Name it `peltdev`. On the next screen copy the install command's **token**.
3. On the droplet: `cloudflared service install YOUR_TOKEN`
4. In the tunnel's **Public Hostname** tab: Subdomain `api`, Domain `peltdev.com`,
   Service type **HTTP**, URL `localhost:8000`. Save.
5. Test from anywhere: https://api.peltdev.com/api/meta should show JSON.

The tunnel URL is permanent, so you never edit `API_BASE` again (the new app.js already uses `https://api.peltdev.com`).

## 5. Frontend
Upload the frontend files to GitHub as before. Deploy `cloudflare-worker.js` again
(`wrangler deploy cloudflare-worker.js --name peltdev-storefronts`): it now lets
`api.peltdev.com` through instead of sending it to GitHub Pages. Set `GITHUB_PAGES_ORIGIN` in it.

## Everyday commands
| | |
|---|---|
| Logs | `journalctl -u peltdev -f` |
| Restart after changing code or .env | `systemctl restart peltdev` |
| Status | `systemctl status peltdev` |
| Update backend code | copy new `backend/*.py` to `/opt/peltdev/backend/`, `chown peltdev:peltdev` them, restart |
| Manual backup | `peltdev-backup` (files in `/var/backups/peltdev`, auto nightly at 3:17, kept 14 days) |
| Restore DB | stop service, copy a `peltdev-DATE.db` to `/opt/peltdev/backend/peltdev.db`, `chown peltdev:peltdev`, start |

## Notes
- No web ports are open. Only SSH (22) is, so the server can't be reached except through Cloudflare.
- Download a backup copy to your own computer now and then (`scp`): backups on the same server don't survive the server being deleted.
- Security updates install automatically (unattended-upgrades).
- Keep exactly one gunicorn worker (already set). More would start several payment watchers and fight over the SQLite file.
