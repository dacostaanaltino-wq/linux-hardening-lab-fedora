#!/usr/bin/env bash
# scripts/10-ssh.sh – durcissement du service SSH (Fedora / OpenSSH).
#
# Ce que fait le script :
#   1. vérifie que sshd_config inclut bien /etc/ssh/sshd_config.d/*.conf ;
#   2. sauvegarde l'ancien fichier dans /var/backups/hardening-lab/ ;
#   3. écrit /etc/ssh/sshd_config.d/50-hardening.conf ;
#   4. teste la configuration avec `sshd -t` (et revient en arrière si KO) ;
#   5. recharge sshd (reload, pas restart).
#
# ATTENTION (anti-verrouillage) : ne jamais fermer la session SSH ouverte
# avant d'avoir testé une NOUVELLE connexion dans un second terminal.
# Le mot de passe n'est désactivé qu'avec l'option --disable-password, et
# seulement si une clé publique est déjà présente pour l'utilisateur de lab.

set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"

# shellcheck source-path=SCRIPTDIR
# shellcheck source=lib/common.sh
source "$SCRIPT_DIR/lib/common.sh"

SSHD_CONFIG="/etc/ssh/sshd_config"
SSHD_DROPIN="/etc/ssh/sshd_config.d/50-hardening.conf"
LAB_USER="${SUDO_USER:-$(id -un)}"
DISABLE_PASSWORD=0
GEN_KEY=0

usage() {
    cat <<'EOF'
10-ssh.sh – durcissement SSH (clé ed25519, SSHv2, pas de root, drop-in).

Usage : sudo ./scripts/10-ssh.sh [OPTIONS]

Options :
  -u, --user NAME        Utilisateur autorisé en SSH (défaut : $SUDO_USER).
      --disable-password Désactive PasswordAuthentication.
                         À faire SEULEMENT après un test de connexion par clé.
      --genkey           Génère une paire ed25519 pour l'utilisateur de lab
                         si le fichier ~/.ssh/id_ed25519 est absent, et ajoute
                         la clé publique dans authorized_keys (lab uniquement :
                         en vrai, la clé se génère sur le poste client).
  -n, --dry-run          Affiche les actions sans rien modifier.
  -h, --help             Affiche cette aide.

Le script exige LAB_CONFIRM=yes pour modifier le système.
EOF
}

while (($# > 0)); do
    case "$1" in
        -u | --user)
            [[ $# -ge 2 ]] || die "L'option $1 demande un argument."
            LAB_USER="$2"
            shift 2
            ;;
        --disable-password)
            DISABLE_PASSWORD=1
            shift
            ;;
        --genkey)
            GEN_KEY=1
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

((DRY_RUN)) || require_lab_confirm
require_root
require_cmd sshd
require_cmd ssh-keygen

id "$LAB_USER" >/dev/null 2>&1 || die "Utilisateur inconnu : $LAB_USER"
user_home="$(getent passwd "$LAB_USER" | cut -d: -f6)"
[[ -d "$user_home" ]] || die "Dossier personnel introuvable pour $LAB_USER"

log_step "Durcissement SSH pour l'utilisateur $LAB_USER (dry-run=$DRY_RUN)"

# ---------------------------------------------------------------------------
# 1. Vérification de la directive Include dans sshd_config
# ---------------------------------------------------------------------------
if [[ ! -r "$SSHD_CONFIG" ]]; then
    # sshd_config est en 0600 root:root : illisible sans sudo.
    if ((DRY_RUN)); then
        log_warn "$SSHD_CONFIG illisible sans root : contrôle de Include ignoré en dry-run."
    else
        die "Impossible de lire $SSHD_CONFIG (lance avec sudo)."
    fi
elif grep -qE '^[[:space:]]*Include[[:space:]]+/etc/ssh/sshd_config\.d/\*\.conf' "$SSHD_CONFIG"; then
    log_info "sshd_config inclut bien /etc/ssh/sshd_config.d/*.conf"
else
    log_warn "La directive Include est absente de $SSHD_CONFIG."
    log_warn "sshd garde la PREMIÈRE valeur trouvée : le drop-in doit être inclus"
    log_warn "en tête de fichier, sinon 50-hardening.conf serait ignoré."
    backup_file "$SSHD_CONFIG"
    if ((DRY_RUN)); then
        log_info "[DRY-RUN] ajoutait « Include /etc/ssh/sshd_config.d/*.conf » en tête de $SSHD_CONFIG"
    else
        sed -i '1i Include /etc/ssh/sshd_config.d/*.conf' "$SSHD_CONFIG"
        log_info "Directive Include ajoutée en tête de $SSHD_CONFIG"
    fi
fi

# ---------------------------------------------------------------------------
# 2. Clé publique : condition pour couper le mot de passe
# ---------------------------------------------------------------------------
auth_keys="$user_home/.ssh/authorized_keys"

if ((GEN_KEY)) && [[ ! -f "$user_home/.ssh/id_ed25519" ]]; then
    if ((DRY_RUN)); then
        log_info "[DRY-RUN] générait une clé ed25519 dans $user_home/.ssh/"
    else
        run install -d -m 0700 -o "$LAB_USER" -g "$LAB_USER" "$user_home/.ssh"
        run ssh-keygen -t ed25519 -a 100 -N '' -C "lab-$LAB_USER" -f "$user_home/.ssh/id_ed25519"
        log_warn "La clé PRIVÉE est dans $user_home/.ssh/id_ed25519 : copie-la sur ton poste client pour te connecter."
    fi
fi

key_present=0
if [[ -s "$auth_keys" ]] && grep -qE '^(ssh-ed25519|ecdsa-sha2-nistp256|ssh-rsa) ' "$auth_keys"; then
    key_present=1
    log_info "Clé publique présente dans $auth_keys"
elif ((GEN_KEY)) && ((DRY_RUN)); then
    key_present=1
else
    log_warn "Aucune clé publique dans $auth_keys"
fi

if ((DISABLE_PASSWORD)) && ((!key_present)); then
    die "Refus : PasswordAuthentication no sans clé publique = risque de verrouillage.
Fais d'abord : ssh-copy-id -i ~/.ssh/id_ed25519.pub LAB_USER@VM   (depuis ton poste), ou relance avec --genkey."
fi

password_value="yes"
if ((DISABLE_PASSWORD)); then
    password_value="no"
else
    log_warn "PasswordAuthentication reste à yes : c'est volontaire."
    log_warn "Après un test de connexion par clé réussi (2e terminal), relance avec --disable-password."
fi

# ---------------------------------------------------------------------------
# 3. Écriture du drop-in
# ---------------------------------------------------------------------------
write_dropin() {
    local target="$1"
    {
        printf '%s\n' '# Durcissement SSH – lab linux-hardening-lab-fedora'
        printf '%s\n' '# Généré par scripts/10-ssh.sh – ne pas éditer à la main.'
        printf '%s\n' ''
        printf 'PermitRootLogin no\n'
        printf 'PermitEmptyPasswords no\n'
        printf 'PubkeyAuthentication yes\n'
        printf 'PasswordAuthentication %s\n' "$password_value"
        printf 'KbdInteractiveAuthentication no\n'
        printf 'MaxAuthTries 3\n'
        printf 'LoginGraceTime 30\n'
        printf 'X11Forwarding no\n'
        printf 'ClientAliveInterval 300\n'
        printf 'ClientAliveCountMax 2\n'
        printf 'AllowUsers %s\n' "$LAB_USER"
    } >"$target"
}

log_info "Contenu du drop-in $SSHD_DROPIN :"
if ((DRY_RUN)); then
    write_dropin /dev/stdout
    log_info "[DRY-RUN] sauvegarde + écriture de $SSHD_DROPIN"
else
    backup_file "$SSHD_DROPIN"
    install -d -m 0755 /etc/ssh/sshd_config.d
    write_dropin "$SSHD_DROPIN"
    chmod 0600 "$SSHD_DROPIN"
    log_info "Écrit : $SSHD_DROPIN"
fi

# ---------------------------------------------------------------------------
# 4. Test de configuration, puis 5. rechargement
# ---------------------------------------------------------------------------
if ((DRY_RUN)); then
    log_info "[DRY-RUN] lancerait : sshd -t"
    log_info "[DRY-RUN] lancerait : systemctl reload sshd"
else
    log_info "Test de la configuration : sshd -t"
    if ! sshd -t 2>&1 | tee /tmp/sshd-t.log; then
        log_error "Configuration SSH invalide : restauration automatique."
        if [[ -d "$HARDENING_BACKUP_ROOT" ]]; then
            latest="$(find "$HARDENING_BACKUP_ROOT" -mindepth 1 -maxdepth 1 -type d | sort | tail -1)"
            if [[ -n "$latest" && -f "$latest/_etc_ssh_sshd_config.d_50-hardening.conf" ]]; then
                cp -a "$latest/_etc_ssh_sshd_config.d_50-hardening.conf" "$SSHD_DROPIN"
                log_warn "Ancien drop-in restauré depuis $latest"
            else
                rm -f "$SSHD_DROPIN"
                log_warn "Drop-in supprimé (il n'existait pas avant)."
            fi
        fi
        die "Corrige la configuration manuellement. sshd n'a PAS été rechargé."
    fi
    log_info "sshd -t : OK"

    systemctl reload sshd
    log_info "sshd rechargé (reload)."
fi

log_step "Étape SSH terminée"
cat >&2 <<'EOF'

!!! ANTI-VERROUILLAGE !!!
 1. GARDE cette session SSH ouverte.
 2. Ouvre un SECOND terminal et teste :
      ssh -i ~/.ssh/id_ed25519 LAB_USER@ADRESSE-DE-LA-VM
 3. Si la connexion fonctionne, tu peux fermer la première session.
    Si elle échoue, restaure avec : sudo ./scripts/rollback.sh
EOF
