#!/usr/bin/env bash
set -euo pipefail

JAIL_USER="${1:-}"
if [[ -z "${JAIL_USER}" ]]; then
  echo "Usage: sudo $0 <username>"
  exit 1
fi
if [[ "${EUID}" -ne 0 ]]; then
  echo "Run as root (sudo)."
  exit 1
fi

need_cmd() { command -v "$1" >/dev/null 2>&1 || { echo "Missing: $1"; exit 1; }; }
need_cmd docker
need_cmd id

CTR_NAME="${CTR_NAME:-mini}"
IMAGE_NAME="${IMAGE_NAME:-mini-box}"
NET_NAME="${NET_NAME:-mini-net}"

CTR_HOSTNAME="${CTR_HOSTNAME:-shell-jail}"

SHELL_BIN="${SHELL_BIN:-sh}"
WORKDIR_IN_CTR="${WORKDIR_IN_CTR:-/work}"

BUILD_DIR="${BUILD_DIR:-/opt/docker-jail/${IMAGE_NAME}}"
DOCKERFILE_PATH="${DOCKERFILE_PATH:-${BUILD_DIR}/Dockerfile}"

SSHD_DROPIN_DIR="${SSHD_DROPIN_DIR:-/etc/ssh/sshd_config.d}"
SSHD_DROPIN_FILE="${SSHD_DROPIN_FILE:-99-docker-jail.conf}"
DROPIN_PATH="${SSHD_DROPIN_DIR}/${SSHD_DROPIN_FILE}"

WRAPPER_PATH="${WRAPPER_PATH:-/usr/local/bin/enter-${CTR_NAME}}"

echo "[*] User:       ${JAIL_USER}"
echo "[*] Image:      ${IMAGE_NAME}"
echo "[*] Container:  ${CTR_NAME}"
echo "[*] Network:    ${NET_NAME}"
echo "[*] Hostname:   ${CTR_HOSTNAME}"
echo "[*] Build dir:  ${BUILD_DIR}"
echo "[*] Dockerfile: ${DOCKERFILE_PATH}"
echo "[*] Wrapper:    ${WRAPPER_PATH}"

if ! id "${JAIL_USER}" >/dev/null 2>&1; then
  echo "[!] User '${JAIL_USER}' does not exist. Create it first (useradd/adduser)."
  exit 1
fi

if ! getent group docker >/dev/null 2>&1; then
  echo "[*] Creating docker group..."
  groupadd docker
fi

if id -nG "${JAIL_USER}" | tr ' ' '\n' | grep -qx docker; then
  echo "[*] ${JAIL_USER} already in docker group."
else
  echo "[*] Adding ${JAIL_USER} to docker group..."
  usermod -aG docker "${JAIL_USER}"
  echo "[!] ${JAIL_USER} must log out/in for group changes to apply."
fi

mkdir -p "${BUILD_DIR}"
if [[ ! -f "${DOCKERFILE_PATH}" ]]; then
  echo "[*] Writing Dockerfile (includes cat banner) -> ${DOCKERFILE_PATH}"
  cat > "${DOCKERFILE_PATH}" <<'EOF'
FROM alpine:3.20

RUN apk add --no-cache bash ca-certificates coreutils \
  && adduser -D -s /bin/sh dev \
  && mkdir -p /work \
  && chown -R dev:dev /work \
  \
  # Banner shown on login shells (e.g., `sh -l`)
  && mkdir -p /etc/profile.d \
  && cat > /etc/profile.d/shell-jail.sh <<'BANNER'
# Only show in interactive shells
case "$-" in
  *i*) ;;
  *) return ;;
esac

echo
echo "   /\\_/\\    Welcome to shell jail"
echo "  ( o.o )   bonk."
echo "   > ^ <"
echo
BANNER

USER dev
WORKDIR /work

# Keep container alive for exec sessions
CMD ["sh", "-lc", "trap : TERM INT; sleep infinity & wait"]
EOF
  chmod 0644 "${DOCKERFILE_PATH}"
else
  echo "[*] Dockerfile already exists; not overwriting."
fi

if docker image inspect "${IMAGE_NAME}" >/dev/null 2>&1; then
  echo "[*] Image exists: ${IMAGE_NAME}"
else
  echo "[*] Building image: ${IMAGE_NAME}"
  docker build -t "${IMAGE_NAME}" "${BUILD_DIR}"
fi

if docker network inspect "${NET_NAME}" >/dev/null 2>&1; then
  echo "[*] Network exists: ${NET_NAME}"
else
  echo "[*] Creating network: ${NET_NAME}"
  docker network create "${NET_NAME}" >/dev/null
fi

if docker inspect "${CTR_NAME}" >/dev/null 2>&1; then
  echo "[*] Container exists: ${CTR_NAME}"
else
  echo "[*] Creating container: ${CTR_NAME}"
  docker run -d \
    --name "${CTR_NAME}" \
    --restart unless-stopped \
    --network "${NET_NAME}" \
    --hostname "${CTR_HOSTNAME}" \
    "${IMAGE_NAME}" >/dev/null
fi

if [[ "$(docker inspect -f '{{.State.Running}}' "${CTR_NAME}")" != "true" ]]; then
  echo "[*] Starting container: ${CTR_NAME}"
  docker start "${CTR_NAME}" >/dev/null
else
  echo "[*] Container is running."
fi

echo "[*] Installing wrapper: ${WRAPPER_PATH}"
cat > "${WRAPPER_PATH}" <<EOF
#!/usr/bin/env bash
set -euo pipefail
CTR="${CTR_NAME}"
SHELL_BIN="${SHELL_BIN}"
WORKDIR="${WORKDIR_IN_CTR}"

if ! docker inspect "\$CTR" >/dev/null 2>&1; then
  echo "Container \$CTR does not exist."
  exit 1
fi

if [ "\$(docker inspect -f '{{.State.Running}}' "\$CTR")" != "true" ]; then
  docker start "\$CTR" >/dev/null
fi

# Use a login shell so /etc/profile.d banner prints
if [ -t 0 ]; then
  exec docker exec -it -w "\$WORKDIR" "\$CTR" "\$SHELL_BIN" -l
else
  exec docker exec -i  -w "\$WORKDIR" "\$CTR" "\$SHELL_BIN" -l
fi
EOF
chmod 0755 "${WRAPPER_PATH}"
chown root:root "${WRAPPER_PATH}"

echo "[*] Configuring Option B (login shell)..."
if ! grep -qxF "${WRAPPER_PATH}" /etc/shells; then
  echo "${WRAPPER_PATH}" >> /etc/shells
  echo "[*] Added wrapper to /etc/shells"
fi

if command -v chsh >/dev/null 2>&1; then
  chsh -s "${WRAPPER_PATH}" "${JAIL_USER}" || usermod -s "${WRAPPER_PATH}" "${JAIL_USER}"
else
  usermod -s "${WRAPPER_PATH}" "${JAIL_USER}"
fi
echo "[*] Set ${JAIL_USER}'s shell -> ${WRAPPER_PATH}"

echo "[*] Configuring Option A (sshd ForceCommand)..."
mkdir -p "${SSHD_DROPIN_DIR}"

cat > "${DROPIN_PATH}" <<EOF
# Managed by docker-jail-setup.sh
Match User ${JAIL_USER}
    ForceCommand ${WRAPPER_PATH}
    PermitTTY yes
    X11Forwarding no
    AllowTcpForwarding no
EOF
chmod 0644 "${DROPIN_PATH}"

reloaded=0
if command -v systemctl >/dev/null 2>&1; then
  if systemctl is-active sshd >/dev/null 2>&1; then
    systemctl reload sshd && reloaded=1 || true
  elif systemctl is-active ssh >/dev/null 2>&1; then
    systemctl reload ssh && reloaded=1 || true
  fi
fi
if [[ "${reloaded}" -eq 0 ]] && command -v service >/dev/null 2>&1; then
  service ssh reload >/dev/null 2>&1 && reloaded=1 || true
  service sshd reload >/dev/null 2>&1 && reloaded=1 || true
fi

if [[ "${reloaded}" -eq 1 ]]; then
  echo "[*] Reloaded ssh service."
else
  echo "[!] Could not auto-reload sshd. Reload it manually for Option A to apply."
fi

echo
echo "${JAIL_USER} has been sent to shell jail."
echo "Test banner quickly:"
echo "  docker exec -it ${CTR_NAME} ${SHELL_BIN} -l"
echo
echo "Test Option B (local/login shell):"
echo "  su - ${JAIL_USER}"
echo
echo "Test Option A (SSH ForceCommand):"
echo "  ssh ${JAIL_USER}@<host>"
echo
echo "Notes:"
echo " - If you just added ${JAIL_USER} to the docker group, they must log out/in."
echo " - docker group access is powerful; treat as effectively root on many hosts."
echo " - Hostname cannot contain spaces; set to '${CTR_HOSTNAME}'. Banner still says 'shell jail'."

