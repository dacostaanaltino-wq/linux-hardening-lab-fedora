#!/usr/bin/env bash
# audit/baseline.sh – collecte l'état du système AVANT (ou APRÈS) durcissement.
#
# Ce script ne modifie rien : il lit et écrit des fichiers texte dans un
# dossier de sortie. Les sorties brutes contiennent le hostname et les
# utilisateurs : ne pas les publier telles quelles (voir README).
#
# Usage :
#   sudo ./audit/baseline.sh                 # -> evidence/before/
#   sudo ./audit/baseline.sh --output DIR    # dossier personnalisé
#   ./audit/baseline.sh --dry-run            # liste les contrôles, n'écrit rien

set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
REPO_DIR="$(cd -- "$SCRIPT_DIR/.." && pwd)"

# shellcheck source-path=SCRIPTDIR
# shellcheck source=../scripts/lib/common.sh
source "$SCRIPT_DIR/../scripts/lib/common.sh"

OUTPUT_DIR="$REPO_DIR/evidence/before"

usage() {
    cat <<'EOF'
baseline.sh – collecte l'état du système (lecture seule).

Usage : sudo ./audit/baseline.sh [OPTIONS]

Options :
  -o, --output DIR   Dossier de sortie (défaut : evidence/before).
  -n, --dry-run      Affiche les contrôles sans rien écrire.
  -h, --help         Affiche cette aide.

À lancer avec sudo pour les contrôles qui en ont besoin (sshd -T, shadow,
sestatus). Sans sudo, certains contrôles écrivent « permission refusée ».
EOF
}

while (($# > 0)); do
    case "$1" in
        -o | --output)
            [[ $# -ge 2 ]] || die "L'option $1 demande un argument."
            OUTPUT_DIR="$2"
            shift 2
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

log_step "Audit de base vers $OUTPUT_DIR (dry-run=$DRY_RUN)"

# Contrôles : chaque entrée est "nom du fichier|commande à lancer".
# On garde une liste pour pouvoir l'afficher en dry-run.
CHECKS=(
    "00-system.txt|uname -a"
    "01-os-release.txt|cat /etc/fedora-release"
    "10-users-shell.txt|awk -F: '\$7 !~ /(nologin|false)\$/ {print \$1\":\"\$3\":\"\$6\":\"\$7}' /etc/passwd"
    "11-groups.txt|getent group wheel sudo"
    "12-password-status.txt|passwd -S -a"
    "20-sockets.txt|ss -tulpn"
    "21-firewalld.txt|firewall-cmd --list-all"
    "22-firewalld-services.txt|firewall-cmd --get-services"
    "30-units-enabled.txt|systemctl list-unit-files --state=enabled --no-pager"
    "31-units-failed.txt|systemctl --failed --no-pager"
    "40-selinux.txt|sestatus"
    "50-sshd-effective.txt|sshd -T"
    "60-suid-sgid.txt|find / -xdev -type f -perm /6000 -printf '%M %u:%g %p\n'"
    "61-world-writable.txt|find / -xdev -type f -perm -0002 -printf '%M %u:%g %p\n'"
    "62-critical-perms.txt|stat -c '%A %U:%G %n' /etc/passwd /etc/shadow /etc/group /etc/gshadow /etc/sudoers /etc/ssh/sshd_config"
    "70-sudoers-grep.txt|grep -REn 'NOPASSWD|ALL=\(ALL' /etc/sudoers /etc/sudoers.d"
    "80-sysctl.txt|sysctl fs.suid_dumpable net.ipv4.conf.all.rp_filter net.ipv4.conf.all.accept_redirects net.ipv4.tcp_syncookies kernel.dmesg_restrict"
    "90-kernel-pkg.txt|rpm -q kernel --last"
)

if ((DRY_RUN)); then
    log_info "[DRY-RUN] dossier de sortie : $OUTPUT_DIR"
    for entry in "${CHECKS[@]}"; do
        log_info "[DRY-RUN] écrivait ${entry%%|*} <- ${entry#*|}"
    done
    log_info "[DRY-RUN] lynis audit system --quick (si lynis est installé)"
    exit 0
fi

mkdir -p "$OUTPUT_DIR"
log_info "Dossier de sortie : $OUTPUT_DIR"

# save <fichier> <commande...> : enregistre la commande et sa sortie.
save() {
    local out="$OUTPUT_DIR/$1"
    shift
    {
        printf '# commande : %s\n' "$*"
        printf '# date     : %s\n' "$(date -u '+%Y-%m-%dT%H:%M:%SZ')"
        printf '# hôte     : %s\n' "$(uname -n)"
        printf '# %s\n' "---------------------------------------------"
    } >"$out"

    if ! command -v "$1" >/dev/null 2>&1; then
        printf '[commande absente du système : %s]\n' "$1" >>"$out"
        log_warn "Commande absente, contrôle ignoré : $1"
        return 0
    fi

    # On n'interrompt pas l'audit si une commande échoue.
    if ! "$@" >>"$out" 2>&1; then
        printf '\n[code retour non nul pour : %s]\n' "$*" >>"$out"
        log_warn "Contrôle en erreur (voir $out) : $*"
    fi
}

for entry in "${CHECKS[@]}"; do
    file="${entry%%|*}"
    cmd="${entry#*|}"
    log_info "Contrôle : $file"
    # On découpe la commande en mots (aucune commande de la liste ne contient
    # d'espace significatif à l'intérieur d'un argument).
    read -r -a argv <<<"$cmd"
    save "$file" "${argv[@]}"
done

# Lynis est optionnel : il donne un score de durcissement comparable avant/après.
if command -v lynis >/dev/null 2>&1; then
    log_info "Lynis détecté : audit rapide (peut prendre 1 à 2 minutes)"
    lynis audit system --quick --no-colors >"$OUTPUT_DIR/91-lynis.txt" 2>&1 ||
        log_warn "Lynis a retourné une erreur, voir 91-lynis.txt"
else
    printf 'lynis non installé : sudo dnf install lynis\n' >"$OUTPUT_DIR/91-lynis.txt"
    log_warn "Lynis non installé : score non collecté."
fi

# Résumé chiffré : sert au tableau avant/après du README.
# « grep -c » affiche 0 ET retourne 1 quand il n'y a aucune correspondance :
# d'où la capture séparée, sinon « || echo n/a » ajouterait une ligne parasite.
count_matches() {
    local count
    count="$(grep -cE "$1" "$2" 2>/dev/null)" || count=0
    printf '%s' "$count"
}

summary="$OUTPUT_DIR/99-summary.txt"
{
    printf 'Résumé de l audit – %s\n\n' "$(date -u '+%Y-%m-%dT%H:%M:%SZ')"
    printf 'Ports en écoute (tcp/udp)     : %s\n' \
        "$(count_matches '^(tcp|udp)' "$OUTPUT_DIR/20-sockets.txt")"
    printf 'Services activés (unités)     : %s\n' \
        "$(count_matches '\.service' "$OUTPUT_DIR/30-units-enabled.txt")"
    printf 'Fichiers SUID/SGID            : %s\n' \
        "$(count_matches '^-' "$OUTPUT_DIR/60-suid-sgid.txt")"
    printf 'Fichiers world-writable       : %s\n' \
        "$(count_matches '^-' "$OUTPUT_DIR/61-world-writable.txt")"
    printf 'SELinux                       : %s\n' "$(getenforce 2>/dev/null || echo n/a)"
    printf 'Lynis (score)                 : %s\n' \
        "$(grep -i 'hardening index' "$OUTPUT_DIR/91-lynis.txt" 2>/dev/null | tail -1 || true)"
} >"$summary"

log_step "Audit terminé : $OUTPUT_DIR"
log_info "Ne pas publier ces fichiers tels quels (hostname, utilisateurs, IP locales)."
