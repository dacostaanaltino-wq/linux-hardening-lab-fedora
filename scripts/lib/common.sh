#!/usr/bin/env bash
# lib/common.sh – fonctions partagées par les scripts du lab.
#
# Ce fichier n'est pas exécuté directement : il est chargé avec
#     source scripts/lib/common.sh
# Il fournit : le journal (fichier + stderr), le mode --dry-run, les
# sauvegardes, et les garde-fous (root, LAB_CONFIRM=yes).

# shellcheck shell=bash

# Journal commun à tous les scripts (modifiable pour les tests).
: "${HARDENING_LOG_FILE:=/var/log/hardening-lab.log}"
: "${HARDENING_BACKUP_ROOT:=/var/backups/hardening-lab}"

# 0 = exécution réelle, 1 = simulation.
DRY_RUN=0

# ---------------------------------------------------------------------------
# Journal
# ---------------------------------------------------------------------------

# Écrit une ligne dans le journal et sur stderr.
# Usage : _log NIVEAU message...
_log() {
    local level="$1"
    shift
    local line
    line="$(date -u '+%Y-%m-%dT%H:%M:%SZ') [$level] $*"
    printf '%s\n' "$line" >&2
    if _log_sink_ready; then
        printf '%s\n' "$line" >>"$HARDENING_LOG_FILE"
    fi
}

# Vérifie que le fichier de journal existe et est inscriptible.
# En dry-run sans les droits, on continue simplement sur stderr.
_log_sink_ready() {
    [[ -f "$HARDENING_LOG_FILE" && -w "$HARDENING_LOG_FILE" ]] && return 0
    mkdir -p "$(dirname "$HARDENING_LOG_FILE")" 2>/dev/null || return 1
    # Les redirections sont lues de gauche à droite : sans les accolades,
    # l'erreur de « >> » s'afficherait avant que 2>/dev/null ne s'applique.
    { : >>"$HARDENING_LOG_FILE"; } 2>/dev/null || return 1
    return 0
}

log_info() { _log "INFO" "$*"; }
log_warn() { _log "WARN" "$*"; }
log_error() { _log "ERROR" "$*"; }
log_step() { _log "STEP" "$*"; }

# Quitte le script avec un message d'erreur.
die() {
    log_error "$*"
    exit 1
}

# Affiche une ligne de résultat de contrôle (utilisé par verify.sh).
print_result() {
    # usage : print_result PASS|FAIL|WARN "description" "détail"
    printf '%-4s | %-58s | %s\n' "$1" "$2" "${3:-}"
}

# ---------------------------------------------------------------------------
# Exécution (avec prise en compte du dry-run)
# ---------------------------------------------------------------------------

# Exécute une commande simple, ou l'affiche en mode --dry-run.
run() {
    if ((DRY_RUN)); then
        log_info "[DRY-RUN] $*"
        return 0
    fi
    log_info "[EXEC] $*"
    "$@"
}

# Exécute une commande qui contient des tubes ou des redirections.
run_shell() {
    local cmd="$1"
    if ((DRY_RUN)); then
        log_info "[DRY-RUN] $cmd"
        return 0
    fi
    log_info "[EXEC] $cmd"
    bash -c "$cmd"
}

# ---------------------------------------------------------------------------
# Garde-fous
# ---------------------------------------------------------------------------

# Refuse l'exécution si le script n'est pas lancé en root (sauf dry-run).
require_root() {
    if ((DRY_RUN)); then
        log_warn "Mode --dry-run : aucune modification, pas besoin de root."
        return 0
    fi
    if [[ "$(id -u)" -ne 0 ]]; then
        die "Ce script doit être lancé avec sudo (ou lancer avec --dry-run)."
    fi
}

# Refuse toute modification sans LAB_CONFIRM=yes.
require_lab_confirm() {
    if [[ "${LAB_CONFIRM:-}" != "yes" ]]; then
        die "Garde-fou : export LAB_CONFIRM=yes avant de lancer les modifications (ou --dry-run pour simuler)."
    fi
}

# Vérifie la présence d'une commande.
require_cmd() {
    command -v "$1" >/dev/null 2>&1 || die "Commande manquante : $1"
}

# ---------------------------------------------------------------------------
# Sauvegardes
# ---------------------------------------------------------------------------

# Sauvegarde un fichier dans /var/backups/hardening-lab/<horodatage>/.
# Le manifeste (manifest.txt) permet à rollback.sh de tout remettre en place.
backup_file() {
    local src="$1"
    if [[ ! -e "$src" ]]; then
        log_info "Rien à sauvegarder (absent) : $src"
        return 0
    fi
    local stamp dir flat
    stamp="$(date -u '+%Y%m%dT%H%M%SZ')"
    dir="$HARDENING_BACKUP_ROOT/$stamp"
    flat="$(printf '%s' "$src" | sed 's|/|_|g')"
    if ((DRY_RUN)); then
        log_info "[DRY-RUN] sauvegarde $src -> $dir/$flat"
        return 0
    fi
    mkdir -p "$dir"
    cp -a "$src" "$dir/$flat"
    printf '%s\t%s\n' "$src" "$flat" >>"$dir/manifest.txt"
    log_info "Sauvegarde : $src -> $dir/$flat"
}

# ---------------------------------------------------------------------------
# Aide
# ---------------------------------------------------------------------------

# En-tête d'aide commun.
print_help_common() {
    cat <<'EOF'
Options communes :
  -n, --dry-run      Simule : affiche les actions sans rien modifier.
  -h, --help         Affiche cette aide et quitte.

Garde-fou : les scripts qui modifient le système exigent LAB_CONFIRM=yes.
  export LAB_CONFIRM=yes && sudo ./scripts/10-ssh.sh
EOF
}

# Analyse les options communes. Retourne 0 si l'option a été consommée.
# Usage : parse_common_opt "$1"
parse_common_opt() {
    case "$1" in
        -n | --dry-run)
            DRY_RUN=1
            return 0
            ;;
        *)
            return 1
            ;;
    esac
}
