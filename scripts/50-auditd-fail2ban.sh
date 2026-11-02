#!/usr/bin/env bash
# scripts/50-auditd-fail2ban.sh – bonus : traçabilité (auditd) et anti-bruteforce (fail2ban).
#
# Ce que fait le script :
#   1. écrit des règles auditd sur les fichiers sensibles et sur sshd ;
#   2. recharge auditd avec augenrules et vérifie les règles chargées ;
#   3. écrit un jail.local fail2ban aligné sur firewalld ;
#   4. teste la configuration fail2ban (fail2ban-client -t).
#
# Roadmap ANSSI-BP-028 (niveau intermédiaire) : la journalisation des
# événements de sécurité suppose que les écritures sur les fichiers sensibles
# soient tracées. Les règles ci-dessous couvrent ce besoin.

set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"

# shellcheck source-path=SCRIPTDIR
# shellcheck source=lib/common.sh
source "$SCRIPT_DIR/lib/common.sh"

AUDIT_RULES="/etc/audit/rules.d/99-hardening-lab.rules"
FAIL2BAN_JAIL="/etc/fail2ban/jail.local"
BANTIME="1h"
MAXRETRY="5"
FINDTIME="10m"

usage() {
    cat <<'EOF'
50-auditd-fail2ban.sh – règles auditd + jail fail2ban (firewalld).

Usage : sudo ./scripts/50-auditd-fail2ban.sh [OPTIONS]

Options :
      --bantime DUREE   Durée du bannissement fail2ban (défaut : 1h).
      --maxretry N      Nombre d'échecs avant bannissement (défaut : 5).
      --findtime DUREE  Fenêtre d'observation (défaut : 10m).
  -n, --dry-run         Affiche les actions sans rien modifier.
  -h, --help            Affiche cette aide.

Prérequis : sudo dnf install audit fail2ban
Le script exige LAB_CONFIRM=yes pour modifier le système.
EOF
}

while (($# > 0)); do
    case "$1" in
        --bantime)
            [[ $# -ge 2 ]] || die "L'option $1 demande un argument."
            BANTIME="$2"
            shift 2
            ;;
        --maxretry)
            [[ $# -ge 2 ]] || die "L'option $1 demande un argument."
            MAXRETRY="$2"
            shift 2
            ;;
        --findtime)
            [[ $# -ge 2 ]] || die "L'option $1 demande un argument."
            FINDTIME="$2"
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

((DRY_RUN)) || require_lab_confirm
require_root

log_step "auditd et fail2ban (dry-run=$DRY_RUN)"

# ---------------------------------------------------------------------------
# 1. Règles auditd
# ---------------------------------------------------------------------------
# -w : surveillance d'un fichier/dossier en écriture et en changement d'attribut.
# -k : clé de recherche, utilisée avec `ausearch -k <clé>`.
write_audit_rules() {
    local target="$1"
    {
        printf '%s\n' '## Règles auditd – lab linux-hardening-lab-fedora'
        printf '%s\n' '## Recherche : ausearch -i -k identity'
        printf '%s\n' ''
        printf '%s\n' '## Comptes et authentification'
        printf '%s\n' '-w /etc/passwd -p wa -k identity'
        printf '%s\n' '-w /etc/shadow -p wa -k identity'
        printf '%s\n' '-w /etc/group -p wa -k identity'
        printf '%s\n' '-w /etc/gshadow -p wa -k identity'
        printf '%s\n' '-w /etc/security/opasswd -p wa -k identity'
        printf '%s\n' ''
        printf '%s\n' '## Escalade de privilèges'
        printf '%s\n' '-w /etc/sudoers -p wa -k sudoers'
        printf '%s\n' '-w /etc/sudoers.d/ -p wa -k sudoers'
        printf '%s\n' ''
        printf '%s\n' '## Configuration SSH'
        printf '%s\n' '-w /etc/ssh/sshd_config -p wa -k sshd_config'
        printf '%s\n' '-w /etc/ssh/sshd_config.d/ -p wa -k sshd_config'
        printf '%s\n' ''
        printf '%s\n' '## Utilisation de commandes sensibles (exécution)'
        printf '%s\n' '-a always,exit -F arch=b64 -S execve -F path=/usr/sbin/useradd -k user_change'
        printf '%s\n' '-a always,exit -F arch=b64 -S execve -F path=/usr/sbin/usermod -k user_change'
        printf '%s\n' '-a always,exit -F arch=b64 -S execve -F path=/usr/bin/passwd -k user_change'
        printf '%s\n' ''
        printf '%s\n' '## Note : on n utilise PAS « -e 2 » (verrouillage définitif des règles).'
        printf '%s\n' '## Sur un vrai serveur, -e 2 empêche un attaquant de modifier les règles,'
        printf '%s\n' '## mais oblige à redémarrer pour les changer : inadapté à un lab.'
    } >"$target"
}

if ! command -v auditctl >/dev/null 2>&1; then
    log_warn "auditd absent. Installation : sudo dnf install audit"
    log_warn "Règles non installées (le fichier peut tout de même être écrit)."
fi

if ((DRY_RUN)); then
    log_info "[DRY-RUN] écrirait $AUDIT_RULES"
    write_audit_rules /dev/stdout | sed -n '1,6p'
    log_info "[DRY-RUN] lancerait : augenrules --load"
else
    backup_file "$AUDIT_RULES"
    install -d -m 0750 /etc/audit/rules.d
    write_audit_rules "$AUDIT_RULES"
    chmod 0640 "$AUDIT_RULES"
    log_info "Écrit : $AUDIT_RULES"

    if command -v augenrules >/dev/null 2>&1; then
        run augenrules --load
        log_info "Règles chargées. Vérification :"
        auditctl -l | grep -c 'hardening\|identity' || true
        log_info "Recherche d'un événement : sudo ausearch -i -k identity"
    else
        log_warn "augenrules absent : relance après installation du paquet audit."
    fi
fi

# ---------------------------------------------------------------------------
# 2. fail2ban + firewalld
# ---------------------------------------------------------------------------
write_fail2ban_jail() {
    local target="$1"
    {
        printf '%s\n' '# jail.local – lab linux-hardening-lab-fedora'
        printf '%s\n' '# firewalld est le pare-feu du lab : fail2ban bannit via firewallcmd.'
        printf '%s\n' '# Vérification de la syntaxe : fail2ban-client -t'
        printf '%s\n' ''
        printf '%s\n' '[DEFAULT]'
        printf 'bantime  = %s\n' "$BANTIME"
        printf 'findtime = %s\n' "$FINDTIME"
        printf 'maxretry = %s\n' "$MAXRETRY"
        printf '%s\n' 'banaction = firewallcmd-ipset'
        printf '%s\n' 'ignoreip = 127.0.0.1/8 ::1'
        printf '%s\n' ''
        printf '%s\n' '[sshd]'
        printf '%s\n' 'enabled = true'
        printf '%s\n' 'port    = ssh'
        printf '%s\n' '# backend systemd : lit directement journald (Fedora)'
        printf '%s\n' 'backend = systemd'
    } >"$target"
}

if command -v fail2ban-client >/dev/null 2>&1; then
    if ((DRY_RUN)); then
        log_info "[DRY-RUN] écrirait $FAIL2BAN_JAIL"
        write_fail2ban_jail /dev/stdout
    else
        backup_file "$FAIL2BAN_JAIL"
        write_fail2ban_jail "$FAIL2BAN_JAIL"
        chmod 0644 "$FAIL2BAN_JAIL"
        log_info "Écrit : $FAIL2BAN_JAIL"
        if fail2ban-client -t; then
            log_info "Configuration fail2ban valide."
            run systemctl enable --now fail2ban
        else
            log_error "Configuration fail2ban invalide : service non démarré."
            die "Corrige $FAIL2BAN_JAIL puis relance fail2ban-client -t"
        fi
    fi
else
    log_warn "fail2ban absent. Installation : sudo dnf install fail2ban"
    log_warn "Ensuite : sudo ./scripts/50-auditd-fail2ban.sh"
fi

log_step "Étape bonus terminée"
log_info "Suivi des bannissements : sudo fail2ban-client status sshd"
