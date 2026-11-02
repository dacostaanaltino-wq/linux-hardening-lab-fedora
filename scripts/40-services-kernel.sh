#!/usr/bin/env bash
# scripts/40-services-kernel.sh – services inutiles et paramètres du noyau.
#
# Ce que fait le script :
#   1. désactive une liste COURTE et justifiée de services (docs/services.md) ;
#   2. écrit /etc/sysctl.d/99-hardening.conf et l'applique ;
#   3. vérifie que SELinux est en mode enforcing (sans jamais le désactiver).
#
# Aucun service n'est désactivé « à l'aveugle » : chaque nom est justifié
# dans docs/services.md, et un service qui n'existe pas est simplement ignoré.

set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"

# shellcheck source-path=SCRIPTDIR
# shellcheck source=lib/common.sh
source "$SCRIPT_DIR/lib/common.sh"

SYSCTL_DROPIN="/etc/sysctl.d/99-hardening.conf"

# Services sans usage sur un serveur de lab : voir docs/services.md.
# Ne jamais ajouter sshd, firewalld, auditd, chronyd, systemd-* ici.
UNUSED_SERVICES=(
    avahi-daemon.service
    cups.service
    bluetooth.service
    rpcbind.service
    rpcbind.socket
    nfs-server.service
    postfix.service
    vsftpd.service
    telnet.socket
)

usage() {
    cat <<'EOF'
40-services-kernel.sh – services inutiles, sysctl, contrôle SELinux.

Usage : sudo ./scripts/40-services-kernel.sh [OPTIONS]

Options :
      --list-only   Affiche l'état des services et les paramètres noyau,
                    sans rien modifier.
  -n, --dry-run     Affiche les actions sans rien modifier.
  -h, --help        Affiche cette aide.

Le script exige LAB_CONFIRM=yes pour modifier le système.
EOF
}

LIST_ONLY=0
while (($# > 0)); do
    case "$1" in
        --list-only)
            LIST_ONLY=1
            shift
            ;;
        -n | --dry-run)
            DRY_RUN=1
            shift
            ;;
        -h | --help)
            usage
            exit 0
            ;;
        *)
            die "Option inconnue : $1 (voir --help)"
            ;;
    esac
done

if ((LIST_ONLY)); then
    log_step "État des services de la liste"
    for svc in "${UNUSED_SERVICES[@]}"; do
        printf '%-24s %s\n' "$svc" "$(systemctl is-enabled "$svc" 2>/dev/null || echo 'non installé')"
    done
    log_step "Paramètres noyau actuels"
    sysctl net.ipv4.conf.all.rp_filter net.ipv4.conf.all.accept_redirects \
        net.ipv4.conf.all.send_redirects net.ipv4.tcp_syncookies \
        net.ipv4.icmp_echo_ignore_broadcasts net.ipv4.conf.all.accept_source_route \
        net.ipv6.conf.all.accept_redirects kernel.dmesg_restrict kernel.kptr_restrict \
        fs.protected_hardlinks fs.protected_symlinks 2>/dev/null
    exit 0
fi

((DRY_RUN)) || require_lab_confirm
require_root

log_step "Services et noyau (dry-run=$DRY_RUN)"

# ---------------------------------------------------------------------------
# 1. Services inutiles
# ---------------------------------------------------------------------------
for svc in "${UNUSED_SERVICES[@]}"; do
    state="$(systemctl is-enabled "$svc" 2>/dev/null || true)"
    case "$state" in
        enabled | enabled-runtime | static | indirect)
            if [[ "$state" == "static" ]]; then
                # Un service statique ne s'active pas seul : il suit ses sockets
                # ou un autre service. On ne le touche pas.
                log_info "$svc : statique, laissé tel quel"
                continue
            fi
            log_info "Désactivation (arrêt + masquage) : $svc"
            run systemctl stop "$svc" || log_warn "Arrêt de $svc impossible (peut-être déjà arrêté)"
            run systemctl disable --now "$svc" || log_warn "disable de $svc impossible"
            ;;
        *)
            log_info "$svc : non activé (${state:-non installé}), rien à faire"
            ;;
    esac
done

# ---------------------------------------------------------------------------
# 2. Paramètres noyau
# ---------------------------------------------------------------------------
write_sysctl() {
    local target="$1"
    {
        printf '%s\n' '# Paramètres noyau – lab linux-hardening-lab-fedora'
        printf '%s\n' '# Généré par scripts/40-services-kernel.sh'
        printf '%s\n' ''
        printf '%s\n' '# Anti-usurpation : une trame qui arrive par une interface ne doit pas'
        printf '%s\n' '# prétendre venir d une autre interface (rp_filter = reverse path filter).'
        printf '%s\n' 'net.ipv4.conf.all.rp_filter = 1'
        printf '%s\n' 'net.ipv4.conf.default.rp_filter = 1'
        printf '%s\n' ''
        printf '%s\n' '# Refuse les redirections ICMP : elles servent à détourner le trafic.'
        printf '%s\n' 'net.ipv4.conf.all.accept_redirects = 0'
        printf '%s\n' 'net.ipv4.conf.default.accept_redirects = 0'
        printf '%s\n' 'net.ipv6.conf.all.accept_redirects = 0'
        printf '%s\n' 'net.ipv6.conf.default.accept_redirects = 0'
        printf '%s\n' ''
        printf '%s\n' '# Machine finale : elle ne doit pas annoncer de routes aux autres.'
        printf '%s\n' 'net.ipv4.conf.all.send_redirects = 0'
        printf '%s\n' 'net.ipv4.conf.default.send_redirects = 0'
        printf '%s\n' ''
        printf '%s\n' '# Refuse le routage source : une trame ne doit pas venir d un réseau'
        printf '%s\n' '# qui n est pas joignable par l interface d arrivée.'
        printf '%s\n' 'net.ipv4.conf.all.accept_source_route = 0'
        printf '%s\n' 'net.ipv4.conf.default.accept_source_route = 0'
        printf '%s\n' ''
        printf '%s\n' '# SYN cookies : protège contre le remplissage de la file des connexions'
        printf '%s\n' '# (attaque par déni de service sur le handshake TCP).'
        printf '%s\n' 'net.ipv4.tcp_syncookies = 1'
        printf '%s\n' ''
        printf '%s\n' '# Ignore les ping en diffusion (utilisés pour l amplification / le scan).'
        printf '%s\n' 'net.ipv4.icmp_echo_ignore_broadcasts = 1'
        printf '%s\n' ''
        printf '%s\n' '# dmesg réservé à root : évite de fuiter des adresses noyau.'
        printf '%s\n' 'kernel.dmesg_restrict = 1'
        printf '%s\n' ''
        printf '%s\n' '# Masque les adresses du noyau dans /proc.'
        printf '%s\n' 'kernel.kptr_restrict = 1'
        printf '%s\n' ''
        printf '%s\n' '# Protection des liens durs et symboliques contre les attaques dans /tmp.'
        printf '%s\n' 'fs.protected_hardlinks = 1'
        printf '%s\n' 'fs.protected_symlinks = 1'
    } >"$target"
}

if ((DRY_RUN)); then
    log_info "[DRY-RUN] écrirait $SYSCTL_DROPIN"
    write_sysctl /dev/stdout
    log_info "[DRY-RUN] appliquerait : sysctl --system"
else
    backup_file "$SYSCTL_DROPIN"
    write_sysctl "$SYSCTL_DROPIN"
    chmod 0644 "$SYSCTL_DROPIN"
    log_info "Écrit : $SYSCTL_DROPIN"
    # sysctl --system relit tous les fichiers de /etc/sysctl.d : c'est la
    # méthode recommandée par systemd-sysctl(8).
    run sysctl --system
fi

# ---------------------------------------------------------------------------
# 3. SELinux : vérification seulement
# ---------------------------------------------------------------------------
log_step "Contrôle SELinux (aucune modification)"
if command -v getenforce >/dev/null 2>&1; then
    mode="$(getenforce)"
    log_info "SELinux : $mode"
    if [[ "$mode" != "Enforcing" ]]; then
        log_warn "SELinux n'est pas en Enforcing. Ne le désactive jamais : cherche d'abord"
        log_warn "la cause (journalctl -t setroubleshoot, ausearch -m AVC)."
        log_warn "Fichier de configuration : /etc/selinux/config (SELINUX=enforcing + reboot)."
    fi
else
    log_warn "getenforce absent : SELinux semble désactivé au niveau du noyau."
fi

log_step "Étape services et noyau terminée"
