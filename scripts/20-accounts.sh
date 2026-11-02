#!/usr/bin/env bash
# scripts/20-accounts.sh – comptes, mots de passe et permissions.
#
# Ce que fait le script :
#   1. politique de mots de passe (pwquality) ;
#   2. durée de vie des mots de passe (login.defs + chage) ;
#   3. contrôle de sudo (rapport seul : on ne modifie JAMAIS sudoers ici) ;
#   4. umask par défaut (027) ;
#   5. permissions anormales : rapport par défaut, correction avec --apply.

set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"

# shellcheck source-path=SCRIPTDIR
# shellcheck source=lib/common.sh
source "$SCRIPT_DIR/lib/common.sh"

APPLY=0
LOCK_USER=""
LIST_ONLY=0

PWQ_DROPIN="/etc/security/pwquality.conf.d/99-hardening.conf"
LOGIN_DEFS="/etc/login.defs"
UMASK_PROFILE="/etc/profile.d/99-umask.sh"

usage() {
    cat <<'EOF'
20-accounts.sh – politique de mots de passe, comptes, permissions.

Usage : sudo ./scripts/20-accounts.sh [OPTIONS]

Options :
      --list          Liste seulement les comptes (aucune modification).
  -l, --lock NAME     Verrouille le compte NAME (usermod -L + expiration).
                      Refusé pour root et pour les comptes système (UID < 1000).
      --apply         Corrige réellement les permissions du tableau ci-dessous.
                      Sans cette option, le script affiche seulement le rapport.
  -n, --dry-run       Affiche les actions sans rien modifier.
  -h, --help          Affiche cette aide.

Le script exige LAB_CONFIRM=yes pour modifier le système.
EOF
}

while (($# > 0)); do
    case "$1" in
        --apply)
            APPLY=1
            shift
            ;;
        --list)
            LIST_ONLY=1
            shift
            ;;
        -l | --lock)
            [[ $# -ge 2 ]] || die "L'option $1 demande un argument."
            LOCK_USER="$2"
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
    log_step "Liste des comptes avec un shell de connexion"
    awk -F: '$7 !~ /(nologin|false|sync)$/ {printf "%-16s uid=%-6s shell=%s\n", $1, $3, $7}' /etc/passwd
    log_step "État des mots de passe (passwd -S)"
    if [[ "$(id -u)" -eq 0 ]]; then
        passwd -S -a 2>/dev/null | awk '{printf "%-16s %-10s %s\n", $1, $2, $3}'
    else
        log_warn "passwd -S -a demande sudo."
    fi
    exit 0
fi

((DRY_RUN)) || require_lab_confirm
require_root

log_step "Comptes et permissions (dry-run=$DRY_RUN, apply=$APPLY)"

# ---------------------------------------------------------------------------
# 0. Verrouillage d'un compte inutile (demandé explicitement)
# ---------------------------------------------------------------------------
if [[ -n "$LOCK_USER" ]]; then
    target_uid="$(id -u "$LOCK_USER" 2>/dev/null || true)"
    if [[ -z "$target_uid" ]]; then
        die "Utilisateur inconnu : $LOCK_USER"
    fi
    if ((target_uid < 1000)); then
        die "Refus : $LOCK_USER est un compte système (UID $target_uid)."
    fi
    if [[ "$LOCK_USER" == "$(id -un)" ]]; then
        log_warn "Tu verrouilles ton propre compte : à éviter depuis cette session."
    fi
    log_info "Verrouillage de $LOCK_USER (usermod -L + expiration du compte)"
    run usermod -L "$LOCK_USER"
    run chage --expiredate 0 "$LOCK_USER"
    log_info "Compte $LOCK_USER verrouillé. Déverrouillage : sudo usermod -U $LOCK_USER && sudo chage -E -1 $LOCK_USER"
fi

# ---------------------------------------------------------------------------
# 1. Politique de mots de passe : pwquality
# ---------------------------------------------------------------------------
# Fedora lit pwquality.conf PUIS les fichiers de pwquality.conf.d/*.conf :
# le drop-in surcharge donc les valeurs par défaut sans toucher au fichier
# livré par le paquet.
write_pwquality() {
    local target="$1"
    {
        printf '%s\n' '# Politique de mots de passe – lab linux-hardening-lab-fedora'
        printf '%s\n' '# minlen : longueur minimale (12 caractères).'
        printf '%s\n' '# minclass : au moins 3 familles différentes (minuscule, majuscule,'
        printf '%s\n' '#            chiffre, caractère spécial).'
        printf '%s\n' '# maxrepeat : pas plus de 3 caractères identiques de suite.'
        printf '%s\n' '# difok : au moins 3 caractères différents de l ancien mot de passe.'
        printf '%s\n' '# dictcheck : refuse les mots du dictionnaire.'
        printf '%s\n' 'minlen = 12'
        printf '%s\n' 'minclass = 3'
        printf '%s\n' 'maxrepeat = 3'
        printf '%s\n' 'difok = 3'
        printf '%s\n' 'dictcheck = 1'
        printf '%s\n' 'enforce_for_root'
    } >"$target"
}

if ((DRY_RUN)); then
    log_info "[DRY-RUN] écrirait $PWQ_DROPIN"
    write_pwquality /dev/stdout
else
    backup_file "$PWQ_DROPIN"
    install -d -m 0755 /etc/security/pwquality.conf.d
    write_pwquality "$PWQ_DROPIN"
    chmod 0644 "$PWQ_DROPIN"
    log_info "Écrit : $PWQ_DROPIN"
fi

# ---------------------------------------------------------------------------
# 2. Durée de vie des mots de passe
# ---------------------------------------------------------------------------
log_info "Réglages de durée de vie dans $LOGIN_DEFS"
for pair in "PASS_MAX_DAYS 90" "PASS_MIN_DAYS 1" "PASS_WARN_AGE 14"; do
    key="${pair%% *}"
    value="${pair#* }"
    current="$(awk -v k="$key" '$1 == k {print $2}' "$LOGIN_DEFS" | tail -1)"
    if [[ "$current" == "$value" ]]; then
        log_info "$key déjà à $value"
    elif [[ -z "$current" ]]; then
        log_warn "$key absent de $LOGIN_DEFS : à vérifier à la main."
    else
        backup_file "$LOGIN_DEFS"
        run sed -i "s/^${key}[[:space:]].*/${key}\t${value}/" "$LOGIN_DEFS"
        log_info "$key : $current -> $value"
    fi
done

log_info "Application de chage aux comptes humains (UID >= 1000)"
while IFS=: read -r name _uid _rest; do
    [[ "$name" == "nobody" ]] && continue
    run chage --maxdays 90 --mindays 1 --warndays 14 --inactive 30 "$name"
done < <(awk -F: '$3 >= 1000 && $3 < 60000 {print $1":"$3":"$4}' /etc/passwd)

# ---------------------------------------------------------------------------
# 3. sudo : contrôle en lecture seule
# ---------------------------------------------------------------------------
log_step "Contrôle de la configuration sudo (aucune modification)"
sudoers_files=(/etc/sudoers)
while IFS= read -r f; do
    [[ -n "$f" ]] && sudoers_files+=("$f")
done < <(find /etc/sudoers.d -maxdepth 1 -type f 2>/dev/null)

for f in "${sudoers_files[@]}"; do
    [[ -r "$f" ]] || continue
    # Lignes actives qui accordent des droits à autre chose que %wheel.
    matches="$(grep -nE '^[^#].*ALL[[:space:]]*=[[:space:]]*\(ALL' "$f" | grep -v '^[0-9]*:%wheel' || true)"
    if [[ -n "$matches" ]]; then
        log_warn "Droits sudo hors %wheel dans $f :"
        printf '%s\n' "$matches" | while IFS= read -r line; do
            printf '        %s\n' "$line" >&2
        done
    fi
    if grep -qE '^[^#].*NOPASSWD' "$f"; then
        log_warn "NOPASSWD trouvé dans $f (à justifier, sinon à retirer à la main)."
    fi
done
log_info "Les membres du groupe wheel : $(getent group wheel | cut -d: -f4)"

# ---------------------------------------------------------------------------
# 4. umask par défaut
# ---------------------------------------------------------------------------
if ((DRY_RUN)); then
    log_info "[DRY-RUN] écrirait $UMASK_PROFILE (umask 027)"
else
    backup_file "$UMASK_PROFILE"
    {
        printf '%s\n' '# umask 027 : les fichiers créés ne sont pas lisibles par les autres.'
        printf '%s\n' '# (lecture/écriture pour le propriétaire, lecture pour le groupe)'
        printf '%s\n' '# Vérification : umask  -> 0027'
        printf 'umask 027\n'
    } >"$UMASK_PROFILE"
    chmod 0644 "$UMASK_PROFILE"
    log_info "Écrit : $UMASK_PROFILE (effectif à la prochaine connexion)"
fi

# ---------------------------------------------------------------------------
# 5. Permissions anormales
# ---------------------------------------------------------------------------
log_step "Permissions des fichiers sensibles (rapport)"
# format : fichier:permissions_attendues
PERM_CHECKS=(
    "/etc/passwd:0644"
    "/etc/shadow:0000"
    "/etc/group:0644"
    "/etc/gshadow:0000"
    "/etc/sudoers:0440"
    "/etc/ssh/sshd_config:0600"
)

bad_count=0
printf '%-28s %-8s %-8s %s\n' "FICHIER" "ACTUEL" "ATTENDU" "ÉTAT" >&2
for entry in "${PERM_CHECKS[@]}"; do
    file="${entry%%:*}"
    expected="${entry#*:}"
    [[ -e "$file" ]] || {
        printf '%-28s %-8s %-8s %s\n' "$file" "-" "$expected" "absent" >&2
        continue
    }
    actual="$(stat -c '%a' "$file")"
    # 0440 == 440 : on compare en octal, sans les zéros de tête.
    if [[ "$((8#$actual))" -eq "$((8#$expected))" ]]; then
        printf '%-28s %-8s %-8s %s\n' "$file" "$actual" "$expected" "OK" >&2
    else
        printf '%-28s %-8s %-8s %s\n' "$file" "$actual" "$expected" "ANORMAL" >&2
        bad_count=$((bad_count + 1))
        if ((APPLY)); then
            backup_file "$file"
            run chmod "$expected" "$file"
            log_info "Permission corrigée : $file -> $expected"
        fi
    fi
done

if ((bad_count > 0)) && ((!APPLY)); then
    log_warn "$bad_count fichier(s) anormal(aux). Relance avec --apply pour corriger."
fi

log_step "Étape comptes terminée"
