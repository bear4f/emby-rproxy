#!/usr/bin/env bash
# emby-rproxy.sh
# Menu-driven Nginx reverse proxy manager for Emby (Debian-friendly, rollback-safe, self-healing)
# Features: add/list/edit/delete, extra port entries, optional TLS, optional BasicAuth, optional subpath,
# nginx -t/-T validate + automatic rollback, self-heal QUIC/HTTP3 template residues, ensure sites-enabled include for certbot.
set -euo pipefail

# -------------------- config --------------------
SITES_AVAIL="/etc/nginx/sites-available"
SITES_ENAB="/etc/nginx/sites-enabled"
CONF_PREFIX="emby-"
HTPASSWD_PATH="/etc/nginx/.htpasswd-emby"
BACKUP_ROOT="/root"
TOOL_NAME="emby-rproxy"
# ------------------------------------------------

need_root() { [[ "${EUID}" -eq 0 ]] || { echo "请用 root 运行：sudo bash $0"; exit 1; }; }
has_cmd() { command -v "$1" >/dev/null 2>&1; }

prompt() {
  local __var="$1" __msg="$2" __def="${3:-}"
  local input=""
  if [[ -n "$__def" ]]; then
    read -r -p "$__msg [$__def]: " input
    input="${input:-$__def}"
  else
    read -r -p "$__msg: " input
  fi
  printf -v "$__var" "%s" "$input"
}

yesno() {
  local __var="$1" __msg="$2" __def="${3:-y}"
  local input=""
  read -r -p "$__msg (y/n) [$__def]: " input
  input="${input:-$__def}"
  input="$(echo "$input" | tr '[:upper:]' '[:lower:]')"
  [[ "$input" == "y" || "$input" == "yes" ]] && printf -v "$__var" "y" || printf -v "$__var" "n"
}

sanitize_name() { echo "$1" | tr -cd '[:alnum:]._-' | sed 's/^\.*//;s/\.*$//'; }

strip_scheme() {
  local s="$1"
  s="${s#http://}"
  s="${s#https://}"
  echo "$s"
}

is_port() {
  local p="$1"
  [[ "$p" =~ ^[0-9]+$ ]] || return 1
  (( p >= 1 && p <= 65535 )) || return 1
  return 0
}

normalize_ports_csv() {
  local csv="$1"
  csv="$(echo "$csv" | tr -d ' ')"
  csv="${csv#,}"
  csv="${csv%,}"
  echo "$csv"
}

os_info() {
  local name="unknown" ver="unknown" codename="unknown"
  if [[ -r /etc/os-release ]]; then
    # shellcheck disable=SC1091
    . /etc/os-release
    name="${NAME:-unknown}"
    ver="${VERSION_ID:-unknown}"
    codename="${VERSION_CODENAME:-${DEBIAN_CODENAME:-unknown}}"
  fi
  echo "$name|$ver|$codename"
}

apt_install() {
  export DEBIAN_FRONTEND=noninteractive
  apt-get update -y >/dev/null
  apt-get install -y "$@" >/dev/null
}

ensure_deps() {
  apt_install nginx curl ca-certificates rsync
}

ensure_certbot() {
  apt_install certbot python3-certbot-nginx
}

ensure_htpasswd() {
  apt_install apache2-utils
}

backup_nginx() {
  local ts dir
  ts="$(date +%Y%m%d_%H%M%S)"
  dir="${BACKUP_ROOT}/nginx-backup-${ts}"
  mkdir -p "$dir/nginx"
  rsync -a /etc/nginx/ "$dir/nginx/"
  echo "$dir"
}

restore_nginx() {
  local dir="$1"
  rsync -a --delete "$dir/nginx/" /etc/nginx/
}

validate_nginx() {
  local dumpfile="$1"
  nginx -t >/dev/null
  nginx -T >"$dumpfile" 2>/dev/null
}

reload_nginx() {
  systemctl enable nginx >/dev/null 2>&1 || true
  systemctl reload nginx >/dev/null 2>&1 || systemctl restart nginx >/dev/null 2>&1 || true
}

open_fw_ports_ufw() {
  local ports_csv="$1"
  if ! has_cmd ufw; then
    apt_install ufw
  fi
  ufw allow 80/tcp >/dev/null || true
  ufw allow 443/tcp >/dev/null || true
  ports_csv="$(normalize_ports_csv "$ports_csv")"
  [[ -z "$ports_csv" ]] && return 0
  IFS=',' read -r -a arr <<<"$ports_csv"
  for p in "${arr[@]}"; do
    [[ -z "$p" ]] && continue
    ufw allow "${p}/tcp" >/dev/null || true
  done
}

conf_path_for_domain() {
  local domain="$1"
  local safe; safe="$(sanitize_name "$domain")"
  echo "${SITES_AVAIL}/${CONF_PREFIX}${safe}.conf"
}

enabled_path_for_domain() {
  local domain="$1"
  local safe; safe="$(sanitize_name "$domain")"
  echo "${SITES_ENAB}/${CONF_PREFIX}${safe}.conf"
}

# -------------------- Self-heal / Compat --------------------

# Ensure Debian-style include exists so certbot-nginx can find server blocks in sites-enabled.
ensure_sites_enabled_include() {
  local main="/etc/nginx/nginx.conf"
  [[ -f "$main" ]] || return 0

  if grep -qE 'include\s+/etc/nginx/sites-enabled/\*;' "$main"; then
    return 0
  fi

  cp -a "$main" "${main}.bak.$(date +%F_%H%M%S)"

  # Prefer inserting after conf.d include if present; otherwise after "http {"
  if grep -qE 'include\s+/etc/nginx/conf\.d/\*\.conf;' "$main"; then
    sed -i '/include\s\+\/etc\/nginx\/conf\.d\/\*\.conf;/a\    include /etc/nginx/sites-enabled/*;' "$main"
  else
    sed -i '/http\s*{/a\    include /etc/nginx/sites-enabled/*;' "$main"
  fi
}

# Remove or neutralize common QUIC/HTTP3 template residues that break Debian nginx (1.18).
# - Remove nginx.conf default 443 ssl server without certificate
# - Comment nginx.conf QUIC/HTTP3 directives
# - Comment any lines referencing $http3 under /etc/nginx
nginx_self_heal_compat() {
  local ts; ts="$(date +%F_%H%M%S)"
  local main="/etc/nginx/nginx.conf"
  local changed="n"

  [[ -f "$main" ]] || return 0

  # (1) Comment lines containing $http3 anywhere under /etc/nginx (unknown "http3" variable)
  local http3_files
  http3_files="$(grep -RIl '\$http3\b' /etc/nginx 2>/dev/null || true)"
  if [[ -n "$http3_files" ]]; then
    while read -r f; do
      [[ -z "$f" ]] && continue
      cp -a "$f" "${f}.bak.${ts}"
      sed -i '/\$http3\b/s/^/# /' "$f"
    done <<< "$http3_files"
    changed="y"
  fi

  # (2) Comment problematic directives in nginx.conf (quic/http3/ssl_reject_handshake)
  if grep -qiE '\b(quic_bpf|http3|ssl_reject_handshake)\b' "$main"; then
    cp -a "$main" "${main}.bak.${ts}"
    sed -i -E '
      s/^\s*quic_bpf\b/# quic_bpf/;
      s/^\s*http3\b/# http3/;
      s/^\s*ssl_reject_handshake\b/# ssl_reject_handshake/;
      s/^\s*(listen .*quic.*;)\s*$/# \1  # disabled by emby-rproxy/;
    ' "$main"
    changed="y"
  fi

  # (3) Remove a broken default 443 ssl server block in nginx.conf that lacks ssl_certificate
  #     Typical pattern:
  #       server { listen 443 ssl default_server ...; ... (no ssl_certificate) ... }
  if grep -qE 'listen\s+443\s+ssl\s+default_server' "$main"; then
    # detect if there exists a server{} containing listen 443 ssl default_server but no ssl_certificate
    if ! awk '
      BEGIN{in=0;has_listen=0;has_cert=0;}
      /server[[:space:]]*\{/ {in=1;has_listen=0;has_cert=0;}
      in && /listen[[:space:]]+443[[:space:]]+ssl[[:space:]]+default_server/ {has_listen=1;}
      in && /ssl_certificate[[:space:]]+/ {has_cert=1;}
      in && /\}/ {
        if (has_listen && !has_cert) exit 10;
        in=0;
      }
      END{exit 0;}
    ' "$main"; then
      cp -a "$main" "${main}.bak.${ts}"
      # remove the first matching broken server{} block (best-effort)
      awk '
        BEGIN{state=0;lvl=0;match=0;}
        # state 0: normal
        # state 2: buffering first server block candidate
        # state 1: dropping matched broken server block
        {
          if (state==0 && $0 ~ /server[[:space:]]*\{/){
            buf[0]=$0; n=1; state=2; lvl=1; match=0; next
          }
          if (state==2){
            buf[n++]=$0
            if ($0 ~ /listen[[:space:]]+443[[:space:]]+ssl[[:space:]]+default_server/) match=1
            if ($0 ~ /\{/) lvl++
            if ($0 ~ /\}/){lvl--; if (lvl==0){
              if (match==1){
                # decide if cert exists inside buffered block
                has_cert=0
                for(i=0;i<n;i++){ if (buf[i] ~ /ssl_certificate[[:space:]]+/) has_cert=1 }
                if (has_cert==0){
                  # drop this block
                  state=0; next
                }
              }
              # not dropped: print buffered
              for(i=0;i<n;i++) print buf[i]
              state=0; next
            }}
            next
          }
          if (state==0){ print }
        }
      ' "$main" > /tmp/nginx.conf.healed && mv /tmp/nginx.conf.healed "$main"
      changed="y"
    fi
  fi

  # (4) Ensure sites-enabled include for certbot
  ensure_sites_enabled_include && changed="y" || true

  # (5) If changed, try reload (do not hard-fail)
  if [[ "$changed" == "y" ]]; then
    nginx -t >/dev/null 2>&1 && (systemctl restart nginx >/dev/null 2>&1 || true)
  fi
}

# -------------------- Nginx site writer --------------------

write_site_conf() {
  # Write or overwrite a site conf. Does NOT run certbot.
  local domain="$1"
  local origin_host="$2"
  local origin_port="$3"
  local origin_scheme="$4"
  local enable_basicauth="$5"
  local basic_user="$6"
  local basic_pass="$7"
  local use_subpath="$8"
  local subpath="$9"
  local upstream_insecure="${10}"
  local extra_ports_csv="${11}"

  local conf; conf="$(conf_path_for_domain "$domain")"
  local enabled; enabled="$(enabled_path_for_domain "$domain")"
  local origin="${origin_host}:${origin_port}"
  local safe_ports; safe_ports="$(normalize_ports_csv "$extra_ports_csv")"

  local auth_snip=""
  if [[ "$enable_basicauth" == "y" ]]; then
    ensure_htpasswd
    htpasswd -bc "$HTPASSWD_PATH" "$basic_user" "$basic_pass" >/dev/null
    auth_snip=$'auth_basic "Restricted";\n        auth_basic_user_file '"$HTPASSWD_PATH"$';\n'
  fi

  # Location block (shared)
  local location_block=""
  if [[ "$use_subpath" == "y" ]]; then
    location_block=$(cat <<EOL
    location = $subpath { return 301 $subpath/; }

    location ^~ $subpath/ {
        ${auth_snip}proxy_pass $origin_scheme://$origin/;

        proxy_http_version 1.1;

        # 421/Host-dependent origin safe default:
        proxy_set_header Host \$proxy_host;
        proxy_set_header X-Forwarded-Host \$host;

        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto \$scheme;

        proxy_set_header Upgrade \$http_upgrade;
        proxy_set_header Connection \$connection_upgrade;

        proxy_set_header Range \$http_range;
        proxy_set_header If-Range \$http_if_range;
        proxy_buffering off;
        proxy_request_buffering off;
        proxy_read_timeout 3600s;
        proxy_send_timeout 3600s;

        client_max_body_size 500m;

        rewrite ^$subpath/(.*)\$ /\$1 break;
        proxy_redirect ~^(/.*)\$ $subpath\$1;
EOL
)
    if [[ "$origin_scheme" == "https" ]]; then
      [[ "$upstream_insecure" == "y" ]] && location_block+=$'\n        proxy_ssl_verify off;\n'
      location_block+=$'        proxy_ssl_server_name on;\n'
    fi
    location_block+=$'    }\n'
  else
    location_block=$(cat <<EOL
    location / {
        ${auth_snip}proxy_pass $origin_scheme://$origin;

        proxy_http_version 1.1;

        # 421/Host-dependent origin safe default:
        proxy_set_header Host \$proxy_host;
        proxy_set_header X-Forwarded-Host \$host;

        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto \$scheme;

        proxy_set_header Upgrade \$http_upgrade;
        proxy_set_header Connection \$connection_upgrade;

        proxy_set_header Range \$http_range;
        proxy_set_header If-Range \$http_if_range;
        proxy_buffering off;
        proxy_request_buffering off;
        proxy_read_timeout 3600s;
        proxy_send_timeout 3600s;

        client_max_body_size 500m;
EOL
)
    if [[ "$origin_scheme" == "https" ]]; then
      [[ "$upstream_insecure" == "y" ]] && location_block+=$'\n        proxy_ssl_verify off;\n'
      location_block+=$'        proxy_ssl_server_name on;\n'
    fi
    location_block+=$'    }\n'
  fi

  cat > "$conf" <<EOL
# ${TOOL_NAME}: Emby Reverse Proxy for ${domain}
# Managed by ${TOOL_NAME}
# META domain=${domain} origin=${origin_scheme}://${origin} subpath=${subpath} extra_ports=${safe_ports} basicauth=${enable_basicauth}

map \$http_upgrade \$connection_upgrade {
    default upgrade;
    ''      close;
}

# ---- Main entry (80) ----
server {
    listen 80;
    listen [::]:80;
    server_name ${domain};

${location_block}
}
EOL

  # Extra ports: HTTP only by design (so IP:port is easy)
  if [[ -n "${safe_ports// /}" ]]; then
    IFS=',' read -r -a ports <<<"$safe_ports"
    for p in "${ports[@]}"; do
      [[ -z "$p" ]] && continue
      is_port "$p" || { echo "端口非法：$p"; return 1; }
      [[ "$p" == "80" || "$p" == "443" ]] && { echo "额外端口不允许使用 80/443：$p"; return 1; }

      cat >> "$conf" <<EOL

# ---- Extra entry (HTTP) :${p} ----
server {
    listen ${p};
    listen [::]:${p};
    # 使用 _ 接受任意 Host，便于 http://VPS_IP:${p}/ 访问
    server_name _;

${location_block}
}
EOL
    done
  fi

  ln -sf "$conf" "$enabled"
  rm -f "${SITES_ENAB}/default" >/dev/null 2>&1 || true
}

apply_with_rollback() {
  local backup_dir="$1"
  local dumpfile="$2"

  set +e
  validate_nginx "$dumpfile"
  local rc=$?
  set -e
  if [[ $rc -ne 0 ]]; then
    echo "❌ nginx 校验失败（nginx -t/-T），开始回滚..."
    echo "---- nginx -T 输出（含错误）已保存：$dumpfile ----"
    restore_nginx "$backup_dir"
    nginx -t >/dev/null 2>&1 || true
    reload_nginx
    echo "✅ 已回滚并恢复 Nginx。"
    return 1
  fi

  reload_nginx
  return 0
}

certbot_enable_tls() {
  local domain="$1"
  local email="$2"

  ensure_certbot
  # Make sure certbot can see the server block (sites-enabled include)
  ensure_sites_enabled_include
  nginx -t >/dev/null 2>&1 && systemctl reload nginx >/dev/null 2>&1 || true

  certbot --nginx -d "$domain" --agree-tos -m "$email" --non-interactive --redirect
}

print_usage_hint() {
  local domain="$1"
  local subpath="$2"
  local enable_ssl="$3"
  local ports_csv="$4"

  local main="http://${domain}"
  [[ "$enable_ssl" == "y" ]] && main="https://${domain}"

  if [[ "$subpath" != "/" && -n "$subpath" ]]; then
    main="${main}${subpath}"
  else
    main="${main}/"
  fi

  echo
  echo "================ 使用方法（观看走 VPS 流量） ================"
  echo "主入口（推荐）："
  echo "  浏览器：打开 ${main}"
  echo "  Emby 客户端：服务器地址填 ${main%/}"
  echo
  if [[ -n "${ports_csv// /}" ]]; then
    ports_csv="$(normalize_ports_csv "$ports_csv")"
    echo "端口入口（HTTP，不加密，便于 IP 访问）："
    IFS=',' read -r -a ports <<<"$ports_csv"
    for p in "${ports[@]}"; do
      [[ -z "$p" ]] && continue
      echo "  - http://${domain}:${p}/"
      echo "  - http://VPS_IP:${p}/"
    done
    echo "  Emby 客户端同理：可填 http://${domain}:端口 或 http://VPS_IP:端口"
  fi
  echo
  echo "注意："
  echo "  1) 用 IP + HTTPS 访问会证书不匹配（正常现象），推荐用域名走 HTTPS。"
  echo "  2) 额外端口是 HTTP（明文），如需端口也走 HTTPS 可后续扩展（但 IP 访问仍会证书不匹配）。"
  echo "  3) 若回源本身有 Cloudflare/WAF，VPS 回源可能被 403/1020/拦截，这不是 Nginx 问题。"
  echo "============================================================="
  echo
}

# -------------------- Actions --------------------

warn_cf_ports() {
  local ports_csv="$1"
  ports_csv="$(normalize_ports_csv "$ports_csv")"
  [[ -z "$ports_csv" ]] && return 0
  # Cloudflare proxied ports allowlist for HTTP: 80,8080,8880,2052,2082,2086,2095
  # and for HTTPS: 443,2053,2083,2087,2096,8443
  # Our extra ports are HTTP only. If user uses orange cloud, non-allowlist ports won't work through CF.
  local ok_http_ports="80 8080 8880 2052 2082 2086 2095"
  IFS=',' read -r -a arr <<<"$ports_csv"
  for p in "${arr[@]}"; do
    [[ -z "$p" ]] && continue
    for ok in $ok_http_ports; do
      [[ "$p" == "$ok" ]] && continue 2
    done
    echo "⚠️ 提示：端口 ${p} 可能不被 Cloudflare 小黄云代理支持。若开启橙云后无法访问，建议改用 8080/8880/2052/2082/2086/2095 等（或将该记录灰云直连）。"
  done
}

action_add_or_edit() {
  local DOMAIN ORIGIN_HOST ORIGIN_PORT ORIGIN_SCHEME
  local ENABLE_SSL EMAIL ENABLE_UFW
  local ENABLE_BASICAUTH BASIC_USER BASIC_PASS
  local USE_SUBPATH SUBPATH
  local UPSTREAM_INSECURE
  local EXTRA_PORTS

  prompt DOMAIN "访问域名（只填域名，不要 https://）"
  DOMAIN="$(strip_scheme "$DOMAIN")"

  prompt ORIGIN_HOST "源站域名或IP（可误输 http(s)://，会自动去掉）"
  ORIGIN_HOST="$(strip_scheme "$ORIGIN_HOST")"

  prompt ORIGIN_PORT "源站端口" "8096"
  is_port "$ORIGIN_PORT" || { echo "端口不合法：$ORIGIN_PORT"; return 1; }

  prompt ORIGIN_SCHEME "源站协议 http/https" "http"
  [[ "$ORIGIN_SCHEME" == "http" || "$ORIGIN_SCHEME" == "https" ]] || { echo "协议只能是 http 或 https"; return 1; }

  yesno ENABLE_SSL "为主入口申请 Let's Encrypt（将启用 443 并 80->443）" "y"
  EMAIL="admin@${DOMAIN}"
  [[ "$ENABLE_SSL" == "y" ]] && prompt EMAIL "证书邮箱" "$EMAIL"

  yesno ENABLE_UFW "自动用 UFW 放通 80/443 + 额外端口（不影响面板安全组）" "n"

  yesno ENABLE_BASICAUTH "启用 BasicAuth（公网建议开启）" "n"
  BASIC_USER="emby"; BASIC_PASS=""
  if [[ "$ENABLE_BASICAUTH" == "y" ]]; then
    prompt BASIC_USER "BasicAuth 用户名" "emby"
    prompt BASIC_PASS "BasicAuth 密码"
  fi

  yesno USE_SUBPATH "使用子路径（例如 /emby）" "n"
  SUBPATH="/"
  if [[ "$USE_SUBPATH" == "y" ]]; then
    prompt SUBPATH "子路径（以 / 开头，不以 / 结尾）" "/emby"
    [[ "$SUBPATH" == /* ]] || SUBPATH="/$SUBPATH"
    [[ "$SUBPATH" != */ ]] || { echo "子路径不能以 / 结尾"; return 1; }
  fi

  UPSTREAM_INSECURE="n"
  if [[ "$ORIGIN_SCHEME" == "https" ]]; then
    yesno UPSTREAM_INSECURE "源站 HTTPS 为自签/不受信证书（跳过验证）" "n"
  fi

  prompt EXTRA_PORTS "额外端口入口（逗号分隔，可空；例如 18443,28096）" "18443"
  EXTRA_PORTS="$(normalize_ports_csv "$EXTRA_PORTS")"
  if [[ -n "${EXTRA_PORTS// /}" ]]; then
    IFS=',' read -r -a arr <<<"$EXTRA_PORTS"
    for p in "${arr[@]}"; do
      [[ -z "$p" ]] && continue
      is_port "$p" || { echo "额外端口不合法：$p"; return 1; }
      [[ "$p" == "80" || "$p" == "443" ]] && { echo "额外端口不能用 80/443：$p"; return 1; }
    done
  fi

  warn_cf_ports "$EXTRA_PORTS"

  echo
  echo "---- 配置确认 ----"
  echo "入口域名:    $DOMAIN"
  echo "回源:        $ORIGIN_SCHEME://$ORIGIN_HOST:$ORIGIN_PORT"
  echo "子路径:      $SUBPATH"
  echo "主入口 HTTPS: $ENABLE_SSL"
  echo "BasicAuth:   $ENABLE_BASICAUTH"
  echo "UFW:         $ENABLE_UFW"
  echo "额外端口:    ${EXTRA_PORTS:-（无）} (HTTP)"
  echo "------------------"
  echo

  ensure_deps
  ensure_sites_enabled_include
  nginx_self_heal_compat

  local backup dump
  backup="$(backup_nginx)"
  dump="$(mktemp)"
  trap 'rm -f "$dump"' RETURN

  set +e
  write_site_conf "$DOMAIN" "$ORIGIN_HOST" "$ORIGIN_PORT" "$ORIGIN_SCHEME" \
                  "$ENABLE_BASICAUTH" "$BASIC_USER" "$BASIC_PASS" \
                  "$USE_SUBPATH" "$SUBPATH" \
                  "$UPSTREAM_INSECURE" "$EXTRA_PORTS"
  local rc_write=$?
  set -e
  if [[ $rc_write -ne 0 ]]; then
    echo "❌ 写入配置失败，回滚..."
    restore_nginx "$backup"
    reload_nginx
    return 1
  fi

  apply_with_rollback "$backup" "$dump" || return 1

  if [[ "$ENABLE_UFW" == "y" ]]; then
    open_fw_ports_ufw "$EXTRA_PORTS"
  fi

  if [[ "$ENABLE_SSL" == "y" ]]; then
    set +e
    certbot_enable_tls "$DOMAIN" "$EMAIL"
    local rc_cert=$?
    set -e
    if [[ $rc_cert -ne 0 ]]; then
      echo "❌ certbot 配置失败，回滚..."
      restore_nginx "$backup"
      reload_nginx
      return 1
    fi
    apply_with_rollback "$backup" "$dump" || return 1
  fi

  echo "✅ 已生效：$DOMAIN"
  echo "站点配置：$(conf_path_for_domain "$DOMAIN")"
  echo "备份目录：$backup"
  echo

  if [[ "$USE_SUBPATH" == "y" ]]; then
    echo "⚠️ 子路径提示：建议在 Emby 后台把 Base URL 设置为 $SUBPATH，然后重启 Emby。"
    echo
  fi

  print_usage_hint "$DOMAIN" "$SUBPATH" "$ENABLE_SSL" "$EXTRA_PORTS"
  echo "提示：若外网无法访问端口入口，请同时检查云厂商安全组/面板防火墙是否放通该端口。"
}

action_list() {
  echo "=== 现有 Emby 反代（${SITES_AVAIL}/${CONF_PREFIX}*.conf）==="
  shopt -s nullglob
  local files=("${SITES_AVAIL}/${CONF_PREFIX}"*.conf)
  if [[ ${#files[@]} -eq 0 ]]; then
    echo "（空）"
    return 0
  fi

  for f in "${files[@]}"; do
    local meta domain origin subpath ports basicauth
    meta="$(grep -E '^# META ' "$f" | head -n1 || true)"
    domain="$(echo "$meta" | sed -n 's/.*domain=\([^ ]*\).*/\1/p')"
    origin="$(echo "$meta" | sed -n 's/.*origin=\([^ ]*\).*/\1/p')"
    subpath="$(echo "$meta" | sed -n 's/.*subpath=\([^ ]*\).*/\1/p')"
    ports="$(echo "$meta" | sed -n 's/.*extra_ports=\([^ ]*\).*/\1/p')"
    basicauth="$(echo "$meta" | sed -n 's/.*basicauth=\([^ ]*\).*/\1/p')"
    [[ -z "$subpath" ]] && subpath="/"
    [[ -z "$ports" ]] && ports="（无）"
    [[ -z "$basicauth" ]] && basicauth="n"

    echo "- ${domain:-（未知域名）}"
    echo "    回源: ${origin:-（未知）}"
    echo "    子路径: $subpath"
    echo "    额外端口: $ports (HTTP)"
    echo "    BasicAuth: $basicauth"
    echo "    conf: $f"
  done
}

action_delete() {
  local DOMAIN DEL_CERT
  prompt DOMAIN "要删除的访问域名（server_name）"
  DOMAIN="$(strip_scheme "$DOMAIN")"

  local conf enabled
  conf="$(conf_path_for_domain "$DOMAIN")"
  enabled="$(enabled_path_for_domain "$DOMAIN")"

  if [[ ! -f "$conf" && ! -L "$enabled" ]]; then
    echo "没找到该站点：$DOMAIN"
    return 1
  fi

  yesno DEL_CERT "是否同时删除证书（需要你手动执行 certbot delete）" "n"

  ensure_deps
  ensure_sites_enabled_include
  nginx_self_heal_compat

  local backup dump
  backup="$(backup_nginx)"
  dump="$(mktemp)"
  trap 'rm -f "$dump"' RETURN

  rm -f "$enabled" "$conf"

  if ! apply_with_rollback "$backup" "$dump"; then
    return 1
  fi

  echo "✅ 已删除站点：$DOMAIN"
  echo "备份目录：$backup"
  if [[ "$DEL_CERT" == "y" ]] && has_cmd certbot; then
    echo "证书删除请手动执行：certbot delete --cert-name $DOMAIN"
  fi
}

action_nginx_check() {
  echo "nginx -t："
  nginx -t
  echo
  echo "nginx 状态："
  systemctl status nginx --no-pager || true
}

action_uninstall() {
  echo "将卸载本脚本对系统的“管理痕迹”（不卸载 nginx/certbot），包括："
  echo "  - 删除 ${SITES_AVAIL}/${CONF_PREFIX}*.conf 与对应 enabled 链接（可选）"
  echo "  - 不会自动删除证书（如需可手动 certbot delete）"
  echo

  local REMOVE_SITES
  yesno REMOVE_SITES "是否删除所有 ${CONF_PREFIX}*.conf 站点配置" "n"
  if [[ "$REMOVE_SITES" == "y" ]]; then
    ensure_deps
    ensure_sites_enabled_include
    nginx_self_heal_compat

    local backup dump
    backup="$(backup_nginx)"
    dump="$(mktemp)"
    trap 'rm -f "$dump"' RETURN

    rm -f "${SITES_AVAIL}/${CONF_PREFIX}"*.conf 2>/dev/null || true
    rm -f "${SITES_ENAB}/${CONF_PREFIX}"*.conf 2>/dev/null || true

    apply_with_rollback "$backup" "$dump" || true
    echo "✅ 已删除 emby 站点配置。备份目录：$backup"
  else
    echo "未删除任何站点配置。"
  fi

  echo
  echo "脚本文件本身如果你想删除，请手动 rm -f emby-rproxy.sh（或你放置的位置）。"
}

menu() {
  IFS="|" read -r OS_NAME OS_VER OS_CODE < <(os_info)
  echo "=== ${TOOL_NAME}（Emby Nginx 反代管理）==="
  echo "系统识别：${OS_NAME} / ${OS_VER} / ${OS_CODE}"
  echo "提示：确保域名解析到 VPS，80/443 放通；额外端口也要放通（含云厂商安全组）。"
  echo

  while true; do
    echo "========== 菜单 =========="
    echo "1) 添加/覆盖 Emby 反代（含额外端口入口）"
    echo "2) 查看现有反代"
    echo "3) 修改反代（= 覆盖同域名）"
    echo "4) 删除反代"
    echo "5) Nginx 测试与状态"
    echo "6) 卸载（可选删除所有 emby 站点配置）"
    echo "0) 退出"
    echo "=========================="
    read -r -p "请选择: " c
    case "$c" in
      1) action_add_or_edit ;;
      2) action_list ;;
      3) action_add_or_edit ;;
      4) action_delete ;;
      5) action_nginx_check ;;
      6) action_uninstall ;;
      0) exit 0 ;;
      *) echo "无效选项" ;;
    esac
  done
}

need_root
menu
