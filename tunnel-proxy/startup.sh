#!/usr/bin/env bash
# startup.sh -- deployment helper for the LinkPulse tunnel server.
#
# It inspects what is already on the machine (image, container, database,
# certbot certificates, DNS, busy ports, firewall), asks how you want to
# deploy, and then does it: build, replace the container, wait for health and
# roll back automatically if the new container does not come up.
#
# Usage:
#   ./startup.sh                                    interactive
#   ./startup.sh --action restart                   restart the running container
#   ./startup.sh --action update --yes              rebuild, keep existing config
#   IMAGE=tunnel-proxy:new ./startup.sh --action update --no-rebuild --yes
#   ./startup.sh --action redeploy --mode 3 --range 20000-20100 --yes
#   ./startup.sh --action rebuild  --mode 3 --range 20000-20100 --yes
#   ./startup.sh --help
#
# Actions (asked interactively when omitted):
#   restart   restart the existing container as-is (fastest, config unchanged)
#   update    rebuild/use a new image with the existing container configuration
#   redeploy  replace the container with a chosen port/protocol layout
#   rebuild   rebuild the image from source, then redeploy
#   direct    stop the container and run proxy_server.py in the foreground
#   stop      stop the container
#   status    show container/image/certificate/DNS state and recent logs
#
# Deployment modes (for redeploy/rebuild/direct):
#   1) HTTP/HTTPS tunnels only          public 80, 443, 9000
#   2) HTTP + TCP tunnels               + TCP tunnel port range
#   3) HTTP + TCP + UDP tunnels         + TCP and UDP tunnel port range (default)
#   4) Host networking (no -p)          every port bound directly on the host
#   5) Direct Python run (no Docker)    foreground, for debugging
#
# Non-interactive use: pass --yes. With --yes every prompt is answered with its
# default (restart if a container exists, otherwise redeploy; mode 3;
# range $DEFAULT_RANGE; no rebuild unless the image is missing or action=update).
# Missing option values are rejected instead of consuming the next argument.
#
# Tunables (environment):
#   ENV_FILE          .env file (default .env) -- parsed, never executed by the
#                     docker path; `direct` mode sources it (see run_direct)
#   CONTAINER/IMAGE   names (default tunnel-proxy)
#   DATA_DIR          HOST directory mounted at container /data (default /data)
#   LOG_DIR           HOST directory mounted at container /var/log/tunnel-proxy
#                     (default /var/log/tunnel-proxy -- never the whole /var/log)
#   TUNNEL_PORT_RANGE default 20000-20100
#   CONTAINER_MEMORY  --memory value (default 512m; "none" or "" disables)
#   CONTAINER_CPUS    --cpus value   (default 0.5;  "none" or "" disables)
#   BIND_IP           host IP to publish ports on (default "" -> all interfaces)
#
# Update requires an existing container and a local Unix-socket Docker daemon.
# It ignores .env and deployment tunables; --no-rebuild uses IMAGE as-is.
# The script never prints secrets from .env.

set -uo pipefail

SCRIPT_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
cd "$SCRIPT_DIR" || exit 1

ENV_FILE=${ENV_FILE:-.env}
CONTAINER=${CONTAINER:-tunnel-proxy}
IMAGE=${IMAGE:-tunnel-proxy}
DATA_DIR=${DATA_DIR:-/data}
LOG_DIR=${LOG_DIR:-/var/log/tunnel-proxy}
CONTAINER_DATA_DEST=/data
CONTAINER_LOG_DEST=/var/log/tunnel-proxy
DEFAULT_RANGE=${TUNNEL_PORT_RANGE:-20000-20100}
CONTAINER_MEMORY=${CONTAINER_MEMORY:-512m}
CONTAINER_CPUS=${CONTAINER_CPUS:-0.5}
BIND_IP=${BIND_IP:-}

ACTION=""
MODE=""
RANGE=""
RANGE_LO=""
RANGE_HI=""
REBUILD=""
NO_REBUILD=""
ASSUME_YES=""
PREV_IMAGE=""
CONTAINER_EXISTS=""
CONTAINER_STATE=""
DOMAIN=""
CERT_FILE=""
CERT_NOTE=""
SCHEME="https"
PUBLIC_IP=""
IS_ORACLE=""
DOCKER_OK=""
REPLACE_BACKUP=""
REPLACE_STOPPED=0
UPDATE_CONFIG=""
BIND_OPTION=""

# ---------------------------------------------------------------- helpers ---

if [ -t 1 ]; then BOLD=1; DIM=2; RED=31; GRN=32; YEL=33; else BOLD=0; DIM=0; RED=0; GRN=0; YEL=0; fi
c() { printf '\033[%sm%s\033[0m' "$1" "$2"; }
say() { printf '\n%s\n' "$(c "$BOLD" "$*")"; }
warn() { printf '%s %s\n' "$(c "$YEL" "warning:")" "$*"; }
die() { printf '%s %s\n' "$(c "$RED" "error:")" "$*" >&2; exit 1; }
ok() { printf '%s %s\n' "$(c "$GRN" "ok:")" "$*"; }

usage() {
  sed -n '2,/^set -uo pipefail/{ /^set -uo pipefail/d; s/^# \{0,1\}//; p; }' "$SCRIPT_DIR/startup.sh"
  exit 0
}

# Read KEY from .env without exporting or echoing secret values.
env_get() {
  [ -f "$ENV_FILE" ] || return 0
  sed -nE "s/^[[:space:]]*(export[[:space:]]+)?${1}[[:space:]]*=[[:space:]]*//p" "$ENV_FILE" \
    | tail -n1 | tr -d "\"'\r"
}

# True if the current user can read the file (tries sudo -n as a fallback).
SUDO_READ=0
can_read() {
  [ -e "$1" ] || return 1
  if [ -r "$1" ]; then SUDO_READ=0; return 0; fi
  if command -v sudo >/dev/null 2>&1 && sudo -n test -e "$1" 2>/dev/null; then
    SUDO_READ=1
    return 0
  fi
  return 1
}

run_readable() { # run_readable <cmd...>
  if [ "$SUDO_READ" = 1 ]; then sudo -n "$@"; else "$@"; fi
}

port_busy() { # port_busy <tcp-port>
  ss -ltnH 2>/dev/null | awk '{print $4}' | grep -qE "[:.]$1$"
}

port_held_by_us() { # port_held_by_us <host-port>
  docker inspect "$CONTAINER" >/dev/null 2>&1 || return 1
  docker port "$CONTAINER" 2>/dev/null | grep -qE ":$1$"
}

confirm() { # confirm "question" default(y/n)
  local answer
  if [ -n "$ASSUME_YES" ]; then return 0; fi
  read -rp "$1 [${2:-y}] " answer
  answer=${answer:-${2:-y}}
  [ "${answer,,}" = "y" ] || [ "${answer,,}" = "yes" ]
}

# Validate a "MIN-MAX" range (or a single "PORT") and set RANGE_LO/RANGE_HI.
parse_range() {
  local r=$1 lo hi
  if [[ "$r" =~ ^([0-9]+)-([0-9]+)$ ]]; then
    lo=${BASH_REMATCH[1]}; hi=${BASH_REMATCH[2]}
  elif [[ "$r" =~ ^([0-9]+)$ ]]; then
    lo=${BASH_REMATCH[1]}; hi=${BASH_REMATCH[1]}
  else
    return 1
  fi
  # Reject leading zeros: bash treats 08 as an invalid octal in arithmetic.
  case "$lo" in 0[0-9]*) return 1 ;; esac
  case "$hi" in 0[0-9]*) return 1 ;; esac
  # Ports are <= 65535 (5 digits); a longer number would overflow bash arithmetic
  # and could wrap into a valid-looking value.
  [ "${#lo}" -le 5 ] && [ "${#hi}" -le 5 ] || return 1
  RANGE_LO=$((10#$lo))
  RANGE_HI=$((10#$hi))
  [ "$RANGE_LO" -ge 1024 ] && [ "$RANGE_HI" -le 65535 ] && [ "$RANGE_LO" -le "$RANGE_HI" ]
}

publish_args() { # publish_args <host-port> <container-port> [proto] -> echoes -p VALUE
  local hp=$1 cp=$2 proto=${3:-} hip
  if [ -n "$BIND_IP" ]; then
    hip=$BIND_IP
    case "$hip" in *:*) hip="[$hip]" ;; esac   # IPv6 host address in docker -p
    printf '%s:%s:%s%s' "$hip" "$hp" "$cp" "$proto"
  else printf '%s:%s%s' "$hp" "$cp" "$proto"; fi
}

# Canonicalize a path, resolving symlinks even when the leaf does not exist yet.
resolve_path() {
  python3 -c 'import os,sys; print(os.path.realpath(sys.argv[1]))' "$1"
}

# Reject mount sources that resolve to a broad host/system tree (this also
# catches '/tmp/link -> /' style symlinks, not just the literal spelling).
validate_paths() {
  local data_real log_real
  case "$DATA_DIR" in /*) ;; *) die "DATA_DIR must be an absolute path (got '$DATA_DIR')" ;; esac
  case "$LOG_DIR" in /*) ;; *) die "LOG_DIR must be an absolute path (got '$LOG_DIR')" ;; esac
  data_real="$(resolve_path "$DATA_DIR")" || die "could not resolve DATA_DIR '$DATA_DIR'"
  log_real="$(resolve_path "$LOG_DIR")" || die "could not resolve LOG_DIR '$LOG_DIR'"
  case "$data_real" in
    /|/etc|/usr|/bin|/sbin|/lib|/lib64|/proc|/sys|/dev|/boot|/root|/home)
      die "DATA_DIR resolves to '$data_real'; refusing a broad/system mount" ;;
  esac
  case "$log_real" in
    /|/var|/var/log|/etc|/usr|/home|/root|/boot|/proc|/sys|/dev)
      die "LOG_DIR resolves to '$log_real'; refusing a broad/system mount (use a dedicated dir such as /var/log/tunnel-proxy)" ;;
  esac
  # Use the canonical paths for the actual mounts.
  DATA_DIR="$data_real"
  LOG_DIR="$log_real"
}

validate_bind_ip() {
  [ -n "$BIND_IP" ] || return 0
  if ! python3 -c 'import ipaddress,sys; ipaddress.ip_address(sys.argv[1])' "$BIND_IP" 2>/dev/null; then
    die "invalid publish IP '$BIND_IP' (expected an IPv4 or IPv6 address)"
  fi
}

# Validate the .env the way docker --env-file will read it: KEY=VALUE, no shell
# execution. All four required values must be present and non-placeholder.
validate_env_file() {
  [ -f "$ENV_FILE" ] || die "$ENV_FILE not found -- copy .env.example to $ENV_FILE and fill it in"
  local key val
  for key in SHARED_SECRET WILDCARD_DOMAIN DASHBOARD_PASSWORD JWT_SECRET; do
    val=$(env_get "$key")
    if [ -z "$val" ]; then
      die "$ENV_FILE is missing or has an empty '$key' (required for the container to start)"
    fi
    case "$val" in
      *your-*|*YOUR-*|*replace-with*|*REPLACE-WITH*|*placehold*|*PLACEHOLD*|*change_me*|*CHANGE_ME*|*changeme*)
        die "$ENV_FILE still has a placeholder value for '$key'" ;;
    esac
  done
  # docker --env-file does not strip shell quotes; warn instead of passing them
  # through to the server silently.
  if grep -qE "^[[:space:]]*(export[[:space:]]+)?(SHARED_SECRET|WILDCARD_DOMAIN|DASHBOARD_PASSWORD|JWT_SECRET)[[:space:]]*=[[:space:]]*[\"']" "$ENV_FILE"; then
    warn "$ENV_FILE quotes a required value; docker --env-file keeps the quotes literally. Remove them."
  fi
}

resource_args() {
  if [ -n "$CONTAINER_MEMORY" ] && [ "$CONTAINER_MEMORY" != "none" ]; then
    printf -- '--memory\n%s\n' "$CONTAINER_MEMORY"
  fi
  if [ -n "$CONTAINER_CPUS" ] && [ "$CONTAINER_CPUS" != "none" ]; then
    printf -- '--cpus\n%s\n' "$CONTAINER_CPUS"
  fi
}

# --------------------------------------------------------------- detection --

detect() {
  say "Checking this machine"

  DOMAIN=$(env_get WILDCARD_DOMAIN)
  local http_only external_ssl dashboard_pw jwt
  http_only=$(env_get HTTP_ONLY)
  external_ssl=$(env_get EXTERNAL_SSL)
  dashboard_pw=$(env_get DASHBOARD_PASSWORD)
  jwt=$(env_get JWT_SECRET)

  if [ "${http_only,,}" = "true" ] || [ "${http_only,,}" = "1" ]; then SCHEME="http"; else SCHEME="https"; fi

  # .env sanity
  if [ ! -f "$ENV_FILE" ]; then
    warn "no $ENV_FILE here -- copy .env.example to .env and fill it in first"
  else
    printf '  %-16s %s\n' ".env" "$SCRIPT_DIR/$ENV_FILE"
    [ -n "$(env_get SHARED_SECRET)" ] || warn "SHARED_SECRET is empty -- clients will not authenticate"
    [ -n "$DOMAIN" ] || warn "WILDCARD_DOMAIN is empty -- TLS and public URLs will not work"
    if [ -z "$dashboard_pw" ] || [ -z "$jwt" ]; then
      warn "DASHBOARD_PASSWORD and/or JWT_SECRET missing -- the dashboard will fail closed (503)"
    fi
  fi
  printf '  %-16s %s\n' "domain" "${DOMAIN:-<unset>}"

  # Existing certbot certificates (the container keeps them on the data volume)
  local candidate
  for candidate in \
      "$DATA_DIR/letsencrypt/live/$DOMAIN/fullchain.pem" \
      "/etc/letsencrypt/live/$DOMAIN/fullchain.pem"; do
    [ -n "$DOMAIN" ] || break
    if can_read "$candidate"; then
      CERT_FILE=$candidate
      break
    fi
  done
  if [ -n "$CERT_FILE" ]; then
    local end
    end=$(run_readable openssl x509 -noout -enddate -in "$CERT_FILE" 2>/dev/null | cut -d= -f2-)
    if run_readable openssl x509 -noout -checkend 2592000 -in "$CERT_FILE" >/dev/null 2>&1; then
      ok "certbot certificate found: $CERT_FILE"
      CERT_NOTE="reused (expires $end)"
    else
      warn "certificate at $CERT_FILE expires within 30 days ($end) -- the container renews it on start"
      CERT_NOTE="renewed on start (was expiring $end)"
    fi
  elif [ "${http_only,,}" = "true" ]; then
    printf '  %-16s %s\n' "certificates" "none needed (HTTP_ONLY=true)"
    CERT_NOTE="not used (HTTP_ONLY=true)"
  elif [ "${external_ssl,,}" = "true" ]; then
    printf '  %-16s %s\n' "certificates" "external TLS termination (EXTERNAL_SSL=true)"
    CERT_NOTE="external TLS"
  else
    warn "no certificate at $DATA_DIR/letsencrypt/live/$DOMAIN/ -- the container will request one"
    CERT_NOTE="will be requested on start (needs DNS_PROVIDER/CF_API_TOKEN)"
  fi

  # Existing database (clients/tunnels bookkeeping)
  if can_read "$DATA_DIR/tunnel_proxy.db"; then
    printf '  %-16s %s\n' "database" "$DATA_DIR/tunnel_proxy.db ($(run_readable du -h "$DATA_DIR/tunnel_proxy.db" 2>/dev/null | cut -f1))"
  else
    printf '  %-16s %s\n' "database" "not created yet ($DATA_DIR/tunnel_proxy.db)"
  fi

  # Docker + existing container/image
  if command -v docker >/dev/null 2>&1; then
    if ! docker info >/dev/null 2>&1; then
      warn "docker is installed but not usable by $USER (add yourself to the docker group)"
      DOCKER_OK=""
    else
      DOCKER_OK=1
      local status ports
      status=$(docker inspect -f '{{.State.Status}}{{if .State.Health}}/{{.State.Health.Status}}{{end}}' "$CONTAINER" 2>/dev/null)
      ports=$(docker inspect -f '{{range $p, $b := .HostConfig.PortBindings}}{{$p}}->{{range $b}}{{.HostPort}}{{end}} {{end}}' "$CONTAINER" 2>/dev/null)
      if [ -n "$status" ]; then
        CONTAINER_EXISTS=1
        CONTAINER_STATE=$status
        PREV_IMAGE=$(docker inspect -f '{{.Image}}' "$CONTAINER" 2>/dev/null)
        printf '  %-16s %s\n' "container" "$CONTAINER ($status)"
        printf '  %-16s %s\n' "published" "${ports:-none}"
        printf '  %-16s %s\n' "restart policy" "$(docker inspect -f '{{.HostConfig.RestartPolicy.Name}}' "$CONTAINER")"
      else
        printf '  %-16s %s\n' "container" "not present"
      fi
      if docker image inspect "$IMAGE" >/dev/null 2>&1; then
        printf '  %-16s %s\n' "image" "$IMAGE ($(docker inspect -f '{{.Created}}' "$IMAGE" | cut -c1-19))"
      else
        printf '  %-16s %s\n' "image" "not built yet"
      fi
    fi
  else
    warn "docker not found (mode 5 runs the server directly with python3)"
    DOCKER_OK=""
  fi

  # DNS: apex + wildcard must both point here
  if [ -n "$DOMAIN" ]; then
    if curl -fsS --max-time 3 -H "Authorization: Bearer Oracle" \
        http://169.254.169.254/opc/v2/instance/ >/dev/null 2>&1; then
      IS_ORACLE=1
    fi
    PUBLIC_IP=$(curl -fsS --max-time 4 -H "Authorization: Bearer Oracle" \
      http://169.254.169.254/opc/v2/vnics/ 2>/dev/null \
      | python3 -c 'import json,sys;d=json.load(sys.stdin);print(d[0].get("publicIp") or "")' 2>/dev/null)
    [ -n "$PUBLIC_IP" ] || PUBLIC_IP=$(curl -fsS --max-time 4 https://api.ipify.org 2>/dev/null || true)
    local apex wild
    apex=$(getent ahostsv4 "$DOMAIN" 2>/dev/null | awk 'NR==1{print $1}')
    wild=$(getent ahostsv4 "wildcard-probe.$DOMAIN" 2>/dev/null | awk 'NR==1{print $1}')
    printf '  %-16s %s\n' "dns" "$DOMAIN -> ${apex:-<no A record>} | *.$DOMAIN -> ${wild:-<no wildcard>}"
    if [ -n "$PUBLIC_IP" ] && [ -n "$apex" ] && [ "$PUBLIC_IP" != "$apex" ]; then
      warn "DNS does not point at this machine ($PUBLIC_IP)"
    fi
    if [ -z "$wild" ]; then
      warn "no wildcard DNS record -- HTTP tunnels will not resolve"
    fi
  fi

  # Host ports / mounts / resources
  local p busy=""
  for p in 80 443 9000; do
    if port_busy "$p" && ! port_held_by_us "$p"; then busy="$busy $p"; fi
  done
  if [ -n "$busy" ]; then
    warn "port(s) already in use by something else:$busy"
  else
    printf '  %-16s %s\n' "ports 80/443/9000" "available (or already served by $CONTAINER)"
  fi
  printf '  %-16s %s\n' "mounts" "$DATA_DIR -> $CONTAINER_DATA_DEST | $LOG_DIR -> $CONTAINER_LOG_DEST"
  printf '  %-16s %s\n' "resources" "memory=${CONTAINER_MEMORY:-none} cpus=${CONTAINER_CPUS:-none}"
  [ -n "$BIND_IP" ] && printf '  %-16s %s\n' "publish on" "$BIND_IP (all other interfaces untouched)"

  if [ "$IS_ORACLE" = 1 ]; then
    printf '  %-16s %s\n' "cloud" "Oracle Cloud -- VCN security list / NSG must allow the ports too"
  fi
}

# ------------------------------------------------------------------- input --

choose_action() {
  if [ -n "$ACTION" ] || [ -n "$MODE" ]; then
    ACTION=${ACTION:-redeploy}
    return 0
  fi
  if [ -n "$ASSUME_YES" ]; then
    if [ -n "$CONTAINER_EXISTS" ]; then ACTION=restart; else ACTION=redeploy; fi
    return 0
  fi
  say "What do you want to do?"
  if [ -n "$CONTAINER_EXISTS" ]; then
    printf '  %s\n' "$(c "$DIM" "a $CONTAINER container already exists ($CONTAINER_STATE)")"
    cat <<'EOF'
  1) Restart it as-is                 keeps the current ports/configuration
  2) Redeploy with a new layout       change which protocols/ports are exposed
  3) Rebuild the image and redeploy   pick up code changes
  4) Stop the container and run directly (foreground, for debugging)
  5) Stop the container
  6) Show status and recent logs, then exit
  7) Update image, keep configuration rebuild without changing ports/env/mounts
EOF
    local choice
    read -rp "Choose [1]: " choice
    case "${choice:-1}" in
      1) ACTION=restart ;;
      2) ACTION=redeploy ;;
      3) ACTION=rebuild; REBUILD=1 ;;
      4) ACTION=direct ;;
      5) ACTION=stop ;;
      6) ACTION=status ;;
      7) ACTION=update ;;
      *) die "invalid choice '${choice}'" ;;
    esac
  else
    printf '  %s\n' "$(c "$DIM" "no $CONTAINER container is running")"
    cat <<'EOF'
  1) Deploy the container             choose which protocols/ports to expose
  2) Rebuild the image and deploy     pick up code changes
  3) Run proxy_server.py directly     foreground, for debugging
  4) Show status, then exit
EOF
    local choice2
    read -rp "Choose [1]: " choice2
    case "${choice2:-1}" in
      1) ACTION=redeploy ;;
      2) ACTION=rebuild; REBUILD=1 ;;
      3) ACTION=direct ;;
      4) ACTION=status ;;
      *) die "invalid choice '${choice2}'" ;;
    esac
  fi
}

choose_mode() {
  if [ -n "$MODE" ]; then return 0; fi
  if [ -n "$ASSUME_YES" ]; then MODE=3; return 0; fi
  say "How do you want to deploy the tunnel server?"
  cat <<'EOF'
  1) HTTP/HTTPS tunnels only         public 80, 443, 9000
  2) HTTP + TCP tunnels              + a TCP tunnel port range
  3) HTTP + TCP + UDP tunnels        + TCP and UDP tunnel port range   [default]
  4) Host networking (no -p)         container binds host ports directly
  5) Direct Python run (no Docker)   foreground, for debugging
EOF
  local choice
  read -rp "Choose [3]: " choice
  MODE=${choice:-3}
}

pick_range() {
  case "$MODE" in 2|3|4) ;; *) RANGE=""; return 0 ;; esac
  if [ -z "$RANGE" ]; then
    if [ -n "$ASSUME_YES" ]; then
      RANGE=$DEFAULT_RANGE
    else
      local answer
      read -rp "Tunnel port range [${DEFAULT_RANGE}]: " answer
      RANGE=${answer:-$DEFAULT_RANGE}
    fi
  fi
  if ! parse_range "$RANGE"; then
    die "invalid range '$RANGE' (expected MIN-MAX or a single PORT, 1024 <= port <= 65535, e.g. $DEFAULT_RANGE)"
  fi
  RANGE="${RANGE_LO}-${RANGE_HI}"
  local count=$((RANGE_HI - RANGE_LO + 1))
  [ "$count" -le 1000 ] || warn "publishing $RANGE means $count ports -- 100-200 is plenty and keeps DNAT rules small"
  for public_port in 80 443 9000; do
    if [ "$RANGE_LO" -le "$public_port" ] && [ "$RANGE_HI" -ge "$public_port" ]; then
      warn "$RANGE contains public port $public_port -- choose a range above 1024 that avoids 80/443/9000"
      break
    fi
  done
}

maybe_build() {
  [ -n "$DOCKER_OK" ] || die "docker is not usable here"
  if [ -n "$REBUILD" ] && [ -n "$NO_REBUILD" ]; then
    die "--rebuild and --no-rebuild are mutually exclusive"
  fi
  local need=n answer
  if [ -n "$NO_REBUILD" ]; then
    docker image inspect "$IMAGE" >/dev/null 2>&1 || die "image '$IMAGE' is missing but --no-rebuild was given"
  elif [ -n "$REBUILD" ]; then
    need=y
  elif ! docker image inspect "$IMAGE" >/dev/null 2>&1; then
    need=y
  elif [ -z "$ASSUME_YES" ]; then
    read -rp "Rebuild the image from the current sources? [y/N] " answer
    if [ "${answer,,}" = "y" ] || [ "${answer,,}" = "yes" ]; then need=y; fi
  fi
  if [ "$need" = "y" ]; then
    say "Building $IMAGE (the running container is left untouched until the build succeeds)"
    docker build -t "$IMAGE" . || die "docker build failed (the running container was left untouched)"
    ok "image built"
  fi
}

# ---------------------------------------------------------------- firewall --

open_firewall() { # open_firewall <tcp-range|-> <udp-range|->
  [ "$IS_ORACLE" = 1 ] || return 0
  local tcp=$1 udp=$2
  local rules=("INPUT -p tcp -m multiport --dports 80,443,9000 -j ACCEPT")
  [ -n "$tcp" ] && rules+=("INPUT -p tcp --dport $tcp -j ACCEPT")
  [ -n "$udp" ] && rules+=("INPUT -p udp --dport $udp -j ACCEPT")

  say "Host firewall (iptables)"
  echo "Docker publishes container ports through its own DNAT/FORWARD rules, so bridge"
  echo "networking does not need INPUT rules. Host networking and the direct Python run"
  echo "bind the host directly and DO need them."
  local r
  for r in "${rules[@]}"; do echo "  iptables -I $r"; done
  if [ "${MODE}" = 4 ] || [ "${MODE}" = 5 ]; then
    if confirm "Add these iptables rules now?" y; then
      for r in "${rules[@]}"; do
        # shellcheck disable=SC2086
        sudo -n iptables -C $r 2>/dev/null || sudo -n iptables -I $r || warn "could not add: $r"
      done
      command -v netfilter-persistent >/dev/null 2>&1 && sudo -n netfilter-persistent save 2>/dev/null \
        && ok "rules persisted" || echo "  (install iptables-persistent to survive reboots)"
    fi
  fi
  echo "Remember the Oracle VCN security list / NSG as well: allow TCP 80,443,9000${tcp:+ and $tcp}, UDP ${udp:-none}."
}

# ------------------------------------------------------------------ deploy --

container_health() {
  docker inspect -f '{{if .State.Health}}{{.State.Health.Status}}{{else}}none{{end}}' "$CONTAINER" 2>/dev/null || echo missing
}

http_health_ok() {
  if [ "$ACTION" = update ]; then
    # Probe inside the replacement using its saved env, not the current .env or
    # an unrelated HTTP listener on the host. Also works with custom mappings.
    docker exec "$CONTAINER" python3 -c 'import os,urllib.request; urllib.request.urlopen("http://%s:%s/health" % (os.environ.get("HEALTHCHECK_HOST", "127.0.0.1"), os.environ.get("HTTP_PORT", "80")), timeout=4).read()' >/dev/null 2>&1
    return $?
  fi
  local port
  port=$(env_get HTTP_PORT); port=${port:-80}
  curl -fsS --max-time 4 "http://127.0.0.1:${port}/health" >/dev/null 2>&1
}

wait_healthy() {
  local i state h
  printf '  waiting for the container to become healthy'
  for i in $(seq 1 90); do
    state=$(docker inspect -f '{{.State.Status}}' "$CONTAINER" 2>/dev/null || echo missing)
    case "$state" in
      exited|dead|missing|created) echo " -> $state"; return 1 ;;
    esac
    h=$(container_health)
    case "$h" in
      healthy) echo " -> healthy"; return 0 ;;
      unhealthy) echo " -> unhealthy"; return 1 ;;
      none) if http_health_ok; then echo " -> healthy (http)"; return 0; fi ;;
    esac
    printf '.'
    sleep 1
  done
  echo " -> timeout"
  return 1
}

# Restore a container that was moved aside with `docker rename`. This restores
# the exact previous network/ports/env/mounts/restart policy because the
# container object itself was never deleted. Returns non-zero unless both the
# rename and the start succeed.
restore_backup() { # restore_backup <backup-name>
  local backup=$1
  if [ -z "$backup" ]; then
    warn "no previous container to restore"
    return 1
  fi
  if docker inspect "$CONTAINER" >/dev/null 2>&1; then
    docker rm -f "$CONTAINER" >/dev/null 2>&1 || true
  fi
  if ! docker rename "$backup" "$CONTAINER" >/dev/null 2>&1; then
    warn "could not rename '$backup' back to '$CONTAINER' -- it still exists as '$backup'"
    return 1
  fi
  if ! docker start "$CONTAINER" >/dev/null 2>&1; then
    warn "restored '$CONTAINER' but it did not start (start it manually: docker start $CONTAINER)"
    return 1
  fi
  REPLACE_BACKUP=""
  REPLACE_STOPPED=0
  ok "restored the previous container ($CONTAINER)"
  return 0
}

# After a successful deploy, drop the stopped backup and disarm all traps.
clear_backup() {
  trap - INT TERM HUP EXIT
  REPLACE_STOPPED=0
  [ -n "$REPLACE_BACKUP" ] || return 0
  if docker rm "$REPLACE_BACKUP" >/dev/null 2>&1; then
    ok "removed backup container $REPLACE_BACKUP"
  else
    warn "could not remove backup container $REPLACE_BACKUP (it is stopped; remove it manually)"
  fi
  REPLACE_BACKUP=""
}

# Interrupt handling is armed BEFORE the first destructive action, so a
# Ctrl-C/SIGTERM in the stop->rename->healthy window cannot leave the old
# container stopped or half-moved. REPLACE_STOPPED covers the window before the
# rename (start the original again); REPLACE_BACKUP covers it after the rename.
on_interrupt() {
  trap - INT TERM HUP EXIT
  warn "interrupted; restoring the previous container"
  if [ -n "$REPLACE_BACKUP" ]; then
    docker rm -f "$CONTAINER" >/dev/null 2>&1 || true
    restore_backup "$REPLACE_BACKUP" || warn "manual recovery needed: previous container is '$REPLACE_BACKUP'"
  elif [ "$REPLACE_STOPPED" = 1 ]; then
    docker start "$CONTAINER" >/dev/null 2>&1 || warn "could not restart the stopped container '$CONTAINER'"
  fi
  exit 130
}

# Unexpected-error safety net, armed only once the old container has been renamed
# (REPLACE_BACKUP set). Explicit failure paths below handle rollback themselves
# and disarm EXIT first.
on_exit() {
  local rc=$?
  trap - EXIT
  if [ "$rc" -ne 0 ] && [ -n "$REPLACE_BACKUP" ]; then
    docker rm -f "$CONTAINER" >/dev/null 2>&1 || true
    restore_backup "$REPLACE_BACKUP" || warn "manual recovery needed: previous container is '$REPLACE_BACKUP'"
  fi
}

deploy_docker() {
  [ -n "$DOCKER_OK" ] || die "docker is not usable here"
  if [ "$ACTION" != update ]; then
    validate_env_file
    validate_paths
  fi

  local args=(-d --name "$CONTAINER" --restart unless-stopped)
  local tcp="" udp=""
  local line
  while IFS= read -r line; do [ -n "$line" ] && args+=("$line"); done < <(resource_args)

  case "$MODE" in
    1) args+=(-p "$(publish_args 80 80)" -p "$(publish_args 443 443)" -p "$(publish_args 9000 9000)") ;;
    2) tcp=$RANGE
       args+=(-p "$(publish_args 80 80)" -p "$(publish_args 443 443)" -p "$(publish_args 9000 9000)"
              -p "$(publish_args "$RANGE" "$RANGE")"
              -e "TCP_PORT_MIN=${RANGE_LO}" -e "TCP_PORT_MAX=${RANGE_HI}")
       warn "mode 2 does not publish UDP: udp tunnels will not be reachable" ;;
    3) tcp=$RANGE; udp=$RANGE
       args+=(-p "$(publish_args 80 80)" -p "$(publish_args 443 443)" -p "$(publish_args 9000 9000)"
              -p "$(publish_args "$RANGE" "$RANGE")" -p "$(publish_args "$RANGE" "$RANGE" /udp)"
              -e "TCP_PORT_MIN=${RANGE_LO}" -e "TCP_PORT_MAX=${RANGE_HI}"
              -e "UDP_PORT_MIN=${RANGE_LO}" -e "UDP_PORT_MAX=${RANGE_HI}") ;;
    4) args+=(--network host --cap-add NET_BIND_SERVICE
              -e "TCP_PORT_MIN=${RANGE_LO}" -e "TCP_PORT_MAX=${RANGE_HI}"
              -e "UDP_PORT_MIN=${RANGE_LO}" -e "UDP_PORT_MAX=${RANGE_HI}")
       warn "host networking ignores -p: ports 80/443/9000 and $RANGE must be open on the host"
       warn "host mode: the server runs unprivileged and binds 80/443 with CAP_NET_BIND_SERVICE (--cap-add above); without it, use ports >= 1024 or an upstream proxy" ;;
  esac

  # Allow the non-root server to bind 80/443. net.* sysctls are only valid in a
  # private network namespace, hence bridge modes only (host mode inherits the
  # host setting, which the entrypoint must never modify).
  case "$MODE" in 1|2|3) args+=(--sysctl net.ipv4.ip_unprivileged_port_start=0) ;; esac

  args+=(--env-file "$ENV_FILE"
         -v "$DATA_DIR:$CONTAINER_DATA_DEST"
         -v "$LOG_DIR:$CONTAINER_LOG_DEST"
         "$IMAGE")

  if docker inspect "$CONTAINER" >/dev/null 2>&1; then
    say "Replacing the existing container (brief downtime; the old one is kept until the new one is healthy)"
    local backup="${CONTAINER}-backup-$(date +%s)" attempt=0
    while docker inspect "$backup" >/dev/null 2>&1; do
      attempt=$((attempt + 1))
      [ "$attempt" -le 5 ] || die "could not find a free backup name near '$backup'; remove stale '${CONTAINER}-backup-*' containers and retry"
      backup="${CONTAINER}-backup-$(date +%s)-${attempt}"
    done
    REPLACE_BACKUP=""
    REPLACE_STOPPED=0
    # Arm interrupt handling BEFORE the first destructive action.
    trap 'on_interrupt' INT TERM HUP
    if ! docker stop "$CONTAINER" >/dev/null 2>&1; then
      trap - INT TERM HUP
      die "could not stop the existing container '$CONTAINER'; leaving it untouched"
    fi
    REPLACE_STOPPED=1
    if ! docker rename "$CONTAINER" "$backup" >/dev/null 2>&1; then
      docker start "$CONTAINER" >/dev/null 2>&1 || true
      REPLACE_STOPPED=0
      trap - INT TERM HUP
      die "could not move '$CONTAINER' aside; the original was started again"
    fi
    REPLACE_BACKUP="$backup"
    # Arm the unexpected-error safety net only once the backup exists.
    trap 'on_exit' EXIT
    echo "  old container preserved as $backup"
  fi

  if ! start_replacement "${args[@]}"; then
    warn "could not start the replacement container"
    trap - EXIT
    if [ -n "$REPLACE_BACKUP" ]; then
      restore_backup "$REPLACE_BACKUP" || warn "manual recovery needed: previous container is '$REPLACE_BACKUP'"
    fi
    exit 1
  fi
  if ! wait_healthy; then
    echo
    docker logs --tail 40 "$CONTAINER" 2>&1 | sed 's/^/  | /'
    trap - EXIT
    docker rm -f "$CONTAINER" >/dev/null 2>&1 || true
    if [ -n "$REPLACE_BACKUP" ]; then
      if ! restore_backup "$REPLACE_BACKUP"; then
        die "new container is unhealthy and the previous container could not be restored (it is '$REPLACE_BACKUP')"
      fi
      die "new container is unhealthy; the previous container was restored"
    fi
    die "new container is unhealthy"
  fi

  clear_backup
  [ "$ACTION" = update ] || open_firewall "$tcp" "$udp"
}

start_replacement() {
  if [ "$ACTION" = update ]; then
    # The payload stays in memory, not a temporary file or process arguments.
    # Never print it: Config.Env can contain credentials.
    printf '%s' "$UPDATE_CONFIG" | python3 "$SCRIPT_DIR/redeploy_config.py" create "$CONTAINER" \
      || return 1
    docker start "$CONTAINER" >/dev/null
  else
    docker run "$@" >/dev/null
  fi
}

update_container() {
  [ -z "$MODE$RANGE$BIND_OPTION" ] || die "update keeps existing configuration; --mode, --range and --bind cannot be used"
  docker info >/dev/null 2>&1 || die "docker is not usable here"
  DOCKER_OK=1
  docker inspect "$CONTAINER" >/dev/null 2>&1 \
    || die "update requires an existing '$CONTAINER' container; use redeploy for a first deployment"
  # Unlike redeploy, update rebuilds by default, including with --yes.
  [ -n "$NO_REBUILD" ] || REBUILD=1
  maybe_build
  say "Preparing $IMAGE with the configuration saved in $CONTAINER (not $ENV_FILE)"
  UPDATE_CONFIG=$(python3 "$SCRIPT_DIR/redeploy_config.py" prepare "$CONTAINER" "$IMAGE") \
    || die "could not prepare the saved configuration (the existing container was left untouched)"
  deploy_docker
  UPDATE_CONFIG=""
  say "Updated $CONTAINER"
  printf '  %-12s %s\n' "image" "$IMAGE"
  echo "  environment, command, mounts, networking and resource settings preserved"
  docker port "$CONTAINER" 2>/dev/null | sed 's/^/  /' || true
}

run_direct() {
  say "Direct Python run"
  if [ -n "$CONTAINER_EXISTS" ]; then
    confirm "Stop the $CONTAINER container to free ports 80/443/9000?" y || exit 0
    # Stop, do NOT delete: the container keeps its full configuration and can
    # be restored later with `docker start $CONTAINER`.
    docker stop "$CONTAINER" >/dev/null || warn "could not stop $CONTAINER cleanly"
    CONTAINER_EXISTS=""
    echo "  $CONTAINER stopped (still present; restore with 'docker start $CONTAINER')"
  fi
  [ -n "$RANGE" ] || RANGE=$DEFAULT_RANGE
  parse_range "$RANGE" || die "invalid range '$RANGE'"
  export TCP_PORT_MIN=$RANGE_LO TCP_PORT_MAX=$RANGE_HI
  export UDP_PORT_MIN=$RANGE_LO UDP_PORT_MAX=$RANGE_HI
  if [ -f "$ENV_FILE" ]; then
    echo "  Note: direct mode sources $ENV_FILE as a shell file."
    echo "        Only do this with a .env you trust (it is not executed by the docker path)."
    confirm "Source $ENV_FILE and continue?" y || exit 0
    set -a
    # shellcheck disable=SC1090
    . "$ENV_FILE"
    set +a
  fi
  open_firewall "$RANGE" "$RANGE"
  echo
  echo "  Direct mode binds the host directly and needs root (or CAP_NET_BIND_SERVICE)"
  echo "  for ports 80/443/9000; otherwise set HTTP_PORT/HTTPS_PORT/CONTROL_PORT >= 1024."
  exec python3 proxy_server.py
}

restart_container() {
  if [ -z "$CONTAINER_EXISTS" ]; then
    warn "no $CONTAINER container to restart -- deploying instead"
    choose_mode
    pick_range
    validate_paths
    validate_env_file
    deploy_docker
    return
  fi
  say "Restarting $CONTAINER (config unchanged)"
  docker restart "$CONTAINER" >/dev/null || die "could not restart the container"
  if ! wait_healthy; then
    docker logs --tail 40 "$CONTAINER" 2>&1 | sed 's/^/  | /'
    die "container did not become healthy after the restart"
  fi
  ok "restarted"
  echo "  published ports: $(docker port "$CONTAINER" 2>/dev/null | tr '\n' ' ')"
  echo "  run 'redeploy' to change the exposed protocols/range"
}

stop_container() {
  if [ -z "$CONTAINER_EXISTS" ]; then echo "no $CONTAINER container present"; return 0; fi
  confirm "Stop the $CONTAINER container? Tunnels will go offline until it is started again." n || return 0
  docker stop "$CONTAINER" >/dev/null && ok "stopped (start it with 'docker start $CONTAINER' or redeploy)"
}

show_status() {
  local http_port
  http_port=$(env_get HTTP_PORT); http_port=${http_port:-80}
  printf '\n%s\n' "$(c "$BOLD" "container")"
  docker ps -a --filter "name=^/${CONTAINER}$" \
    --format '  {{.Names}} | {{.Image}} | {{.Status}} | {{.Ports}}' 2>/dev/null
  printf '\n%s\n' "$(c "$BOLD" "published ports")"
  docker port "$CONTAINER" 2>/dev/null | sed 's/^/  /' || true
  printf '\n%s\n' "$(c "$BOLD" "health")"
  local code
  code=$(curl -s -o /dev/null -w '%{http_code}' --max-time 4 "http://127.0.0.1:${http_port}/health" 2>/dev/null)
  echo "  http://127.0.0.1:${http_port}/health -> ${code:-unreachable}"
  printf '\n%s\n' "$(c "$BOLD" "recent logs")"
  docker logs --tail 15 "$CONTAINER" 2>&1 | sed 's/^/  | /'
}

# ----------------------------------------------------------------- summary --

summary() {
  local http_port
  http_port=$(env_get HTTP_PORT); http_port=${http_port:-80}
  say "Deployed"
  printf '  %-12s %s\n' "container" "$CONTAINER ($(docker inspect -f '{{.State.Status}}/{{if .State.Health}}{{.State.Health.Status}}{{else}}n/a{{end}}' "$CONTAINER" 2>/dev/null))"
  printf '  %-12s %s\n' "image" "$IMAGE"
  printf '  %-12s %s\n' "domain" "$DOMAIN"
  printf '  %-12s %s\n' "health" "${SCHEME}://$DOMAIN/health"
  printf '  %-12s %s\n' "dashboard" "${SCHEME}://$DOMAIN/  (DASHBOARD_PASSWORD)"
  printf '  %-12s %s\n' "control" "$DOMAIN:9000"
  printf '  %-12s %s\n' "http port" "$http_port"
  case "$MODE" in
    2|3) printf '  %-12s %s\n' "tcp tunnels" "$DOMAIN:$RANGE (each tunnel gets one port from the range)"
         [ "$MODE" = 3 ] && printf '  %-12s %s\n' "udp tunnels" "$DOMAIN:$RANGE" ;;
    4)   printf '  %-12s %s\n' "tcp/udp" "$DOMAIN:$RANGE (host networking)" ;;
  esac
  printf '  %-12s %s\n' "tls" "$CERT_NOTE"
  echo
  echo "Clients:"
  echo "  linkpulse http 8080 -u myapp --server $DOMAIN:9000 --token <SHARED_SECRET>"
  echo "  linkpulse http 8080 -u myapp --lease --server $DOMAIN:9000 --token <SHARED_SECRET>"
  echo "  linkpulse tcp 22 --remote-port ${RANGE_LO:-20000} --server $DOMAIN:9000 --token <SHARED_SECRET>"
}

# -------------------------------------------------------------------- main --

while [ $# -gt 0 ]; do
  case "$1" in
    --action)
      [ $# -ge 2 ] || die "--action requires a value (restart|update|redeploy|rebuild|direct|stop|status)"
      ACTION=$2; shift 2 ;;
    --mode)
      [ $# -ge 2 ] || die "--mode requires a value (1-5)"
      MODE=$2; shift 2 ;;
    --range)
      [ $# -ge 2 ] || die "--range requires a value (MIN-MAX or a single port)"
      RANGE=$2; shift 2 ;;
    --bind)
      [ $# -ge 2 ] || die "--bind requires a host IP"
      BIND_IP=$2; BIND_OPTION=1; shift 2 ;;
    --rebuild) REBUILD=1; shift ;;
    --no-rebuild) NO_REBUILD=1; shift ;;
    -y|--yes) ASSUME_YES=1; shift ;;
    -h|--help) usage ;;
    --) shift; break ;;
    -*) die "unknown argument '$1' (try --help)" ;;
    *) die "unexpected argument '$1' (try --help)" ;;
  esac
done

[ -z "$MODE" ] || [[ "$MODE" =~ ^[1-5]$ ]] || die "--mode must be 1-5"
[ -z "$ACTION" ] || [[ "$ACTION" =~ ^(restart|update|redeploy|rebuild|direct|stop|status)$ ]] \
  || die "--action must be restart, update, redeploy, rebuild, direct, stop or status"
[ "$ACTION" = "rebuild" ] && REBUILD=1
# Mode 5 is the legacy shorthand for "run directly".
[ "$MODE" = "5" ] && [ -z "$ACTION" ] && ACTION=direct

[ "$ACTION" = update ] || detect
choose_action
[ "$ACTION" = update ] || validate_bind_ip

case "$ACTION" in
  status) show_status; exit 0 ;;
  stop) stop_container; exit 0 ;;
  restart) restart_container; summary; exit 0 ;;
  update) update_container; exit 0 ;;
  direct) choose_mode; pick_range; run_direct ;;
esac

# redeploy / rebuild
choose_mode
pick_range
validate_paths
validate_env_file
maybe_build
deploy_docker
summary
