#!/usr/bin/env bash
# startup.sh -- interactive deployment helper for the LinkPulse tunnel server.
#
# It inspects what is already on the machine (image, container, database,
# certbot certificates, DNS, busy ports, firewall), asks how you want to
# deploy, and then does it: build, replace the container, wait for health and
# roll back automatically if the new container does not come up.
#
# Usage:
#   ./startup.sh                                    interactive
#   ./startup.sh --action restart                   restart the running container
#   ./startup.sh --action redeploy --mode 3 --range 20000-20100 --yes
#   ./startup.sh --action rebuild  --mode 3 --range 20000-20100 --yes
#   ./startup.sh --help
#
# Actions (asked interactively when omitted):
#   restart   restart the existing container as-is (fastest, config unchanged)
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
# The script never prints secrets from .env.

set -uo pipefail

SCRIPT_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
cd "$SCRIPT_DIR" || exit 1

ENV_FILE=${ENV_FILE:-.env}
CONTAINER=${CONTAINER:-tunnel-proxy}
IMAGE=${IMAGE:-tunnel-proxy}
DATA_DIR=${DATA_DIR:-/data}
LOG_DIR=${LOG_DIR:-/var/log}
DEFAULT_RANGE=${TUNNEL_PORT_RANGE:-20000-20100}

ACTION=""
MODE=""
RANGE=""
REBUILD=""
ASSUME_YES=""
PREV_IMAGE=""
CONTAINER_EXISTS=""
CONTAINER_STATE=""
DOMAIN=""
CERT_FILE=""
CERT_NOTE=""
PUBLIC_IP=""
IS_ORACLE=""

# ---------------------------------------------------------------- helpers ---

if [ -t 1 ]; then BOLD=1; DIM=2; RED=31; GRN=32; YEL=33; else BOLD=0; DIM=0; RED=0; GRN=0; YEL=0; fi
c() { printf '\033[%sm%s\033[0m' "$1" "$2"; }
say() { printf '\n%s\n' "$(c "$BOLD" "$*")"; }
warn() { printf '%s %s\n' "$(c "$YEL" "warning:")" "$*"; }
die() { printf '%s %s\n' "$(c "$RED" "error:")" "$*" >&2; exit 1; }
ok() { printf '%s %s\n' "$(c "$GRN" "ok:")" "$*"; }

usage() {
  sed -n '2,24p' "$0" | sed 's/^# \{0,1\}//'
  exit 0
}

# Read KEY from .env without exporting or echoing secrets.
env_get() {
  [ -f "$ENV_FILE" ] || return 0
  sed -nE "s/^[[:space:]]*$1[[:space:]]*=[[:space:]]*//p" "$ENV_FILE" | tail -1 | tr -d "\"'\r"
}

# True if the current user can read the file (tries sudo -n as a fallback).
readable() {
  [ -f "$1" ] || [ -e "$1" ] && [ -r "$1" ] && return 0
  if command -v sudo >/dev/null 2>&1 && sudo -n test -e "$1" 2>/dev/null; then
    if [ -r "$1" ]; then return 0; fi
    SUDO_READ=1
    return 0
  fi
  return 1
}

run_readable() { # run_readable <cmd...>
  if [ "${SUDO_READ:-0}" = 1 ]; then sudo -n "$@"; else "$@"; fi
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

# --------------------------------------------------------------- detection --

detect() {
  say "Checking this machine"

  DOMAIN=$(env_get WILDCARD_DOMAIN)
  local http_only external_ssl dashboard_pw jwt
  http_only=$(env_get HTTP_ONLY)
  external_ssl=$(env_get EXTERNAL_SSL)
  dashboard_pw=$(env_get DASHBOARD_PASSWORD)
  jwt=$(env_get JWT_SECRET)

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

  # Existing certbot certificates (the container keeps them on /data/letsencrypt)
  local candidate
  for candidate in \
      "$DATA_DIR/letsencrypt/live/$DOMAIN/fullchain.pem" \
      "/etc/letsencrypt/live/$DOMAIN/fullchain.pem"; do
    [ -n "$DOMAIN" ] || break
    if [ -e "$candidate" ]; then
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
  if [ -e "$DATA_DIR/tunnel_proxy.db" ]; then
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
    PUBLIC_IP=$(curl -fsS --max-time 4 -H "Authorization: Bearer Oracle" \
      http://169.254.169.254/opc/v2/vnics/ 2>/dev/null \
      | python3 -c 'import json,sys;d=json.load(sys.stdin);print(d[0].get("publicIp") or "")' 2>/dev/null)
    if [ -n "$PUBLIC_IP" ]; then IS_ORACLE=1; else
      PUBLIC_IP=$(curl -fsS --max-time 4 https://api.ipify.org 2>/dev/null || true)
    fi
    if [ -z "$PUBLIC_IP" ] && curl -fsS --max-time 3 -H "Authorization: Bearer Oracle" \
        http://169.254.169.254/opc/v2/instance/ >/dev/null 2>&1; then
      IS_ORACLE=1
    fi
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

  # Host ports
  local p busy=""
  for p in 80 443 9000; do
    if port_busy "$p" && ! port_held_by_us "$p"; then busy="$busy $p"; fi
  done
  if [ -n "$busy" ]; then
    warn "port(s) already in use by something else:$busy"
  else
    printf '  %-16s %s\n' "ports 80/443/9000" "available (or already served by $CONTAINER)"
  fi

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
    local answer
    read -rp "Tunnel port range [${DEFAULT_RANGE}]: " answer
    RANGE=${answer:-$DEFAULT_RANGE}
  fi
  [[ "$RANGE" =~ ^([0-9]+)-([0-9]+)$ ]] || die "invalid range '$RANGE' (expected MIN-MAX, e.g. $DEFAULT_RANGE)"
  local lo=${BASH_REMATCH[1]} hi=${BASH_REMATCH[2]}
  [ "$lo" -ge 1024 ] && [ "$hi" -le 65535 ] && [ "$lo" -lt "$hi" ] \
    || die "invalid range '$RANGE' (1024 <= MIN < MAX <= 65535)"
  [ $((hi - lo)) -le 1000 ] || warn "publishing $RANGE means $((hi - lo + 1)) ports -- 100-200 is plenty"
}

maybe_build() {
  if [ -z "$DOCKER_OK" ]; then die "docker is not usable here"; fi
  local answer="n"
  if [ -n "$REBUILD" ]; then answer=y
  elif ! docker image inspect "$IMAGE" >/dev/null 2>&1; then answer=y
  else
    read -rp "Rebuild the image from the current sources? [y/N] " answer
  fi
  if [ "${answer,,}" = "y" ] || [ "${answer,,}" = "yes" ]; then
    say "Building $IMAGE"
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

wait_healthy() {
  local i state
  printf '  waiting for the container to become healthy'
  for i in $(seq 1 90); do
    state=$(docker inspect -f '{{if .State.Health}}{{.State.Health.Status}}{{else}}{{.State.Status}}{{end}}' "$CONTAINER" 2>/dev/null || echo missing)
    case "$state" in
      healthy) echo " -> healthy"; return 0 ;;
      unhealthy|exited|dead|missing) echo " -> $state"; return 1 ;;
    esac
    printf '.'
    sleep 1
  done
  echo " -> timeout"
  return 1
}

rollback() {
  [ -n "$PREV_IMAGE" ] || return 1
  warn "rolling back to the previous image"
  docker rm -f "$CONTAINER" >/dev/null 2>&1
  docker run -d --name "$CONTAINER" --restart unless-stopped \
    -p 80:80 -p 443:443 -p 9000:9000 \
    --env-file "$ENV_FILE" \
    -v "$DATA_DIR:$DATA_DIR" -v "$LOG_DIR:$LOG_DIR" \
    "$PREV_IMAGE" >/dev/null || return 1
  wait_healthy
}

deploy_docker() {
  [ -n "$DOCKER_OK" ] || die "docker is not usable here"
  local args=(-d --name "$CONTAINER" --restart unless-stopped)
  local tcp="" udp=""

  case "$MODE" in
    1) args+=(-p 80:80 -p 443:443 -p 9000:9000) ;;
    2) tcp=$RANGE; args+=(-p 80:80 -p 443:443 -p 9000:9000 -p "$RANGE:$RANGE"
         -e "TCP_PORT_MIN=${RANGE%-*}" -e "TCP_PORT_MAX=${RANGE#*-}")
       warn "mode 2 does not publish UDP: udp tunnels will not be reachable" ;;
    3) tcp=$RANGE; udp=$RANGE; args+=(-p 80:80 -p 443:443 -p 9000:9000
         -p "$RANGE:$RANGE" -p "$RANGE:$RANGE/udp"
         -e "TCP_PORT_MIN=${RANGE%-*}" -e "TCP_PORT_MAX=${RANGE#*-}"
         -e "UDP_PORT_MIN=${RANGE%-*}" -e "UDP_PORT_MAX=${RANGE#*-}") ;;
    4) args+=(--network host -e "TCP_PORT_MIN=${RANGE%-*}" -e "TCP_PORT_MAX=${RANGE#*-}"
         -e "UDP_PORT_MIN=${RANGE%-*}" -e "UDP_PORT_MAX=${RANGE#*-}")
       warn "host networking ignores -p: ports 80/443/9000 and $RANGE must be open on the host" ;;
  esac
  args+=(--env-file "$ENV_FILE" -v "$DATA_DIR:$DATA_DIR" -v "$LOG_DIR:$LOG_DIR" "$IMAGE")

  if docker inspect "$CONTAINER" >/dev/null 2>&1; then
    say "Replacing the existing container (brief downtime)"
    docker rm -f "$CONTAINER" >/dev/null || die "could not remove the old container"
  fi
  docker run "${args[@]}" >/dev/null || { warn "docker run failed"; rollback; exit 1; }
  if ! wait_healthy; then
    echo
    docker logs --tail 40 "$CONTAINER" 2>&1 | sed 's/^/  | /'
    rollback || die "new container is unhealthy and there is nothing to roll back to"
    exit 1
  fi
  open_firewall "$tcp" "$udp"
}

run_direct() {
  say "Direct Python run"
  if [ -n "$CONTAINER_EXISTS" ]; then
    confirm "Stop the $CONTAINER container to free ports 80/443/9000?" y || exit 0
    docker rm -f "$CONTAINER" >/dev/null
    CONTAINER_EXISTS=""
  fi
  [ -n "$RANGE" ] || RANGE=$DEFAULT_RANGE
  export TCP_PORT_MIN=${RANGE%-*} TCP_PORT_MAX=${RANGE#*-}
  export UDP_PORT_MIN=${RANGE%-*} UDP_PORT_MAX=${RANGE#*-}
  if [ -f "$ENV_FILE" ]; then set -a; . "./$ENV_FILE"; set +a; fi
  open_firewall "$RANGE" "$RANGE"
  echo
  exec python3 proxy_server.py
}

restart_container() {
  [ -n "$CONTAINER_EXISTS" ] || { warn "no $CONTAINER container to restart -- deploying instead"; deploy_docker; return; }
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
  [ -n "$CONTAINER_EXISTS" ] || { echo "no $CONTAINER container present"; return 0; }
  confirm "Stop the $CONTAINER container? Tunnels will go offline until it is started again." n || return 0
  docker stop "$CONTAINER" >/dev/null && ok "stopped (start it with 'docker start $CONTAINER' or redeploy)"
}

show_status() {
  printf '\n%s\n' "$(c "$BOLD" "container")"
  docker ps -a --filter "name=^/${CONTAINER}$" \
    --format '  {{.Names}} | {{.Image}} | {{.Status}} | {{.Ports}}' 2>/dev/null
  printf '\n%s\n' "$(c "$BOLD" "published ports")"
  docker port "$CONTAINER" 2>/dev/null | sed 's/^/  /' || true
  printf '\n%s\n' "$(c "$BOLD" "health")"
  local code
  code=$(curl -s -o /dev/null -w '%{http_code}' --max-time 4 "http://127.0.0.1/health" 2>/dev/null)
  echo "  http://127.0.0.1/health -> ${code:-unreachable}"
  printf '\n%s\n' "$(c "$BOLD" "recent logs")"
  docker logs --tail 15 "$CONTAINER" 2>&1 | sed 's/^/  | /'
}

# ----------------------------------------------------------------- summary --

summary() {
  say "Deployed"
  printf '  %-12s %s\n' "container" "$CONTAINER ($(docker inspect -f '{{.State.Status}}/{{if .State.Health}}{{.State.Health.Status}}{{else}}n/a{{end}}' "$CONTAINER" 2>/dev/null))"
  printf '  %-12s %s\n' "image" "$IMAGE"
  printf '  %-12s %s\n' "domain" "$DOMAIN"
  printf '  %-12s %s\n' "health" "https://$DOMAIN/health"
  printf '  %-12s %s\n' "dashboard" "https://$DOMAIN/  (DASHBOARD_PASSWORD)"
  printf '  %-12s %s\n' "control" "$DOMAIN:9000"
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
  echo "  linkpulse tcp 22 --remote-port ${RANGE%-*} --server $DOMAIN:9000 --token <SHARED_SECRET>"
}

# -------------------------------------------------------------------- main --

while [ $# -gt 0 ]; do
  case "$1" in
    --action) ACTION=${2:-}; shift 2 ;;
    --mode) MODE=${2:-}; shift 2 ;;
    --range) RANGE=${2:-}; shift 2 ;;
    --rebuild) REBUILD=1; shift ;;
    --no-rebuild) REBUILD=; shift ;;
    -y|--yes) ASSUME_YES=1; shift ;;
    -h|--help) usage ;;
    *) die "unknown argument '$1' (try --help)" ;;
  esac
done

[ -z "$MODE" ] || [[ "$MODE" =~ ^[1-5]$ ]] || die "--mode must be 1-5"
[ -z "$ACTION" ] || [[ "$ACTION" =~ ^(restart|redeploy|rebuild|direct|stop|status)$ ]] \
  || die "--action must be restart, redeploy, rebuild, direct, stop or status"
[ "$ACTION" = "rebuild" ] && REBUILD=1
# Legacy shorthand: --mode 5 means "run directly".
[ "$MODE" = "5" ] && [ -z "$ACTION" ] && ACTION=direct

detect
choose_action

case "$ACTION" in
  status) show_status; exit 0 ;;
  stop) stop_container; exit 0 ;;
  restart) restart_container; summary; exit 0 ;;
  direct) choose_mode; pick_range; run_direct ;;
esac

# redeploy / rebuild
choose_mode
pick_range
maybe_build
deploy_docker
summary