#!/usr/bin/env bash
# emby-rproxy.sh
# Menu-driven Nginx reverse proxy manager for Emby
# Features: add/list/edit/delete, extra port entries, optional TLS, optional BasicAuth, optional subpath,
# nginx -t/-T validate + automatic rollback, Debian-friendly.
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
  # strip http:// or https:// from a value
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
  # input: " 18443,  28096 ,"
  # output: "18443,28096" (dedup not guaranteed but trimmed)
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
  # nginx -t + nginx -T (full dump)
  # NOTE: capture stderr to dumpfile too, so errors are visible.
  local dumpfile="$1"
  nginx -t >/dev/null
  nginx -T >"$dumpfile" 2>&1
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

# ---------------- Cloudflare port hint (section 3) ----------------
cf_supported_port_warn() {
  local p="$1"
  # Common Cloudflare proxied ports (non-exhaustive, but covers usual choices)
  local ok="80 443 2052 2053 2082 2083 2086 2087 2095 2096 8080 8443 8880"
  if echo " $ok " | grep -q " $p "; then
    return 0
  fi
  echo "⚠️ 提示：端口 $p 可能不被 Cloudflare 小黄云代理支持。若开启橙云后无法访问，建议改用 443/8443/2053/2083/2087/2096/8080/8880 等。"
}
# -----------------------------------------------------------------

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

  # BasicAuth snippet
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

        client_max_body_size 50m;

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
    # NOTE: section 1 - permanently fix Host header to avoid 421 behind Cloudflare/WAF
    location_block=$(cat <<'EOL'
    location / {
        ${auth_snip}proxy_pass ${origin_scheme}://${origin};

        proxy_http_version 1.1;

        proxy_set_header Host $proxy_host;
        proxy_set_header X-Forwarded-Host $host;

        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;

        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection $connection_upgrade;

        proxy_set_header Range $http_range;
        proxy_set_header If-Range $http_if_range;
        proxy_buffering off;
        proxy_request_buffering off;
        proxy_read_timeout 3600s;
        proxy_send_timeout 3600s;

        client_max_body_size 50m;
EOL
)
    # The above heredoc used single quotes to preserve $variables, now we substitute bash vars manually.
    location_block="${location_block//'${auth_snip}'/$auth_snip}"
    location_block="${location_block//'${origin_scheme}'/$origin_scheme}"
    location_block="${location_block//'${origin}'/$origin}"

    if [[ "$origin_scheme" == "https" ]]; then
      [[ "$upstream_insecure" == "y" ]] && location_block+=$'\n        proxy_ssl_verify off;\n'
      location_block+=$'        proxy_ssl_server_name on;\n'
    fi
    location_block+=$'    }\n'
  fi

  # META line: parse-friendly
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
  # certbot modifies existing conf (adds 443 server + redirects 80 -> 443)
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
  echo "============================================================="
  echo
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

    # Cloudflare port hint
    for p in "${arr[@]}"; do
      [[ -z "$p" ]] && continue
      cf_supported_port_warn "$p"
    done
  fi

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

  local backup dump
  backup="$(backup_nginx)"
  dump="$(mktemp)"
  trap 'rm -f "$dump"' RETURN

  # 1) Write config
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

  # 2) Validate + reload (rollback on fail)
  apply_with_rollback "$backup" "$dump" || return 1

  # 3) UFW open ports (optional)
  if [[ "$ENABLE_UFW" == "y" ]]; then
    open_fw_ports_ufw "$EXTRA_PORTS"
  fi

  # 4) TLS (optional) then validate again
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
  local DOMAIN
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
  local backup dump
  backup="$(backup_nginx)"
  dump="$(mktemp)"
  trap 'rm -f "$dump"' RETURN

  rm -f "$enabled" "$conf"

  # Validate + reload with rollback
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

  yesno REMOVE_SITES "是否删除所有 ${CONF_PREFIX}*.conf 站点配置" "n"
  if [[ "$REMOVE_SITES" == "y" ]]; then
    ensure_deps
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