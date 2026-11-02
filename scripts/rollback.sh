#!/usr/bin/env bash
# scripts/rollback.sh – restaure les fichiers sauvegardés par les scripts du lab.
#
# Chaque script qui modifie un fichier appelle backup_file() de lib/common.sh :
# le fichier est copié dans /var/backups/hardening-lab/<horodatage>/ avec un
# manifeste (chemin d'origine -> nom du fichier de sauvegarde).
# rollback.sh relit ce manifeste et remet les fichiers en place.

set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"

# shellcheck source-path=SCRIPTDIR
# shellcheck source=lib/common.sh
source "$SCRIPT_DIR/lib/common.sh"

TARGET_STAMP=""

usage() {
    cat <<'EOF'
rollback.sh – restaure les fichiers depuis une sauvegarde.

Usage : sudo ./scripts/rollback.sh [OPTIONS]

Options :
      --list             Liste les sauvegardes disponibles et quitte.
  -t, --timestamp TS     Restaure la sauvegarde TS (ex. 20260101T120000Z).
                         Par défaut : la plus récente.
  -n, --dry-run          Affiche ce qui serait restauré, sans rien écrire.
  -h, --help             Affiche cette aide.

Après une restauration, sshd est rechargé et les paramètres noyau réappliqués.
Le script exige LAB_CONFIRM=yes pour modifier le système.
EOF
}

list_backups() {
    if [[ ! -d "$HARDENING_BACKUP_ROOT" ]]; then
        log_warn "Aucune sauvegarde : $HARDENING_BACKUP_ROOT n'existe pas."
        return 0
    fi
    find "$HARDENING_BACKUP_ROOT" -mindepth 1 -maxdepth 1 -type d | sort
}

LIST_ONLY=0
while (($# > 0)); do
    case "$1" in
        --list)
            LIST_ONLY=1
            shift
            ;;
        -t | --timestamp)
            [[ $# -ge 2 ]] || die "L'option $1 demande un argument."
            TARGET_STAMP="$2"
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

if ((LIST_ONLY)); then
    log_step "Sauvegardes disponibles dans $HARDENING_BACKUP_ROOT"
    backups="$(list_backups)"
    if [[ -z "$backups" ]]; then
        log_warn "Aucune sauvegarde."
    else
        printf '%s\n' "$backups" >&2
    fi
    exit 0
fi

((DRY_RUN)) || require_lab_confirm
require_root

if [[ -n "$TARGET_STAMP" ]]; then
    backup_dir="$HARDENING_BACKUP_ROOT/$TARGET_STAMP"
else
    backup_dir="$(list_backups | sort | tail -1)"
fi

[[ -n "${backup_dir:-}" && -d "$backup_dir" ]] || die "Sauvegarde introuvable (voir --list)."
[[ -f "$backup_dir/manifest.txt" ]] || die "Manifeste absent dans $backup_dir."

log_step "Restauration depuis $backup_dir (dry-run=$DRY_RUN)"

while IFS=$'\t' read -r original flat; do
    [[ -n "$original" ]] || continue
    if [[ ! -f "$backup_dir/$flat" ]]; then
        log_warn "Sauvegarde manquante pour $original : ignoré."
        continue
    fi
    log_info "Restauration : $backup_dir/$flat -> $original"
    if ((DRY_RUN)); then
        log_info "[DRY-RUN] cp -a $backup_dir/$flat $original"
        continue
    fi
    if [[ -e "$original" ]]; then
        backup_file "$original" # sauvegarde de l'état actuel avant écrasement
    fi
    mkdir -p "$(dirname "$original")"
    cp -a "$backup_dir/$flat" "$original"
done <"$backup_dir/manifest.txt"

if ((DRY_RUN)); then
    log_info "[DRY-RUN] lancerait : sshd -t && systemctl reload sshd ; sysctl --system"
    log_step "Simulation terminée"
    exit 0
fi

# Recharger les services concernés, sans jamais couper l'accès SSH brutalement.
if sshd -t 2>/dev/null; then
    systemctl reload sshd && log_info "sshd rechargé."
else
    log_error "sshd -t en échec après restauration : ne pas recharger, vérifier à la main."
fi

sysctl --system >/dev/null 2>&1 && log_info "Paramètres noyau réappliqués."

log_step "Restauration terminée"
log_info "Pense à relancer : sudo ./scripts/verify.sh"
