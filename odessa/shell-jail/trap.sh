#!/usr/bin/env bash
set -euo pipefail

if ! dpkg -l | grep -q docker; then
    echo "[*] Docker not installed, installing"
    sleep 2
    curl -fsSL get.docker.com -o get-docker.sh && sh get-docker.sh
    echo "[*] Docker installed, setting up jail on users"
fi

if [[ ! -f ./jail.sh ]]; then
    echo "Error: jail.sh not found in current directory"
    exit 1
fi

if [[ ! -x ./jail.sh ]]; then
    echo "[*] Jail is not executable, setting it to executable"
    chmod +x jail.sh
fi

mapfile -t USERS < <(awk -F: '{print $1}' /etc/passwd)

echo "[*] Found ${#USERS[@]} users in /etc/passwd"

for user in "${USERS[@]}"; do
    read -r -p "[*] Jail '$user'? [y/N/q] " answer
    case "${answer,,}" in
        y|yes)
          echo "[*] Jailing $user"
            sudo ./jail.sh "$user"
            ;;
        q|quit)
            echo "[*] Aborted."
            exit 0
            ;;
        *)
            echo "[*] Skipping $user"
            ;;
    esac
done

echo "[*] Done."
