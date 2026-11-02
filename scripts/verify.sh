#!/usr/bin/env bash
# scripts/verify.sh – vérifie que le durcissement est réellement appliqué.
#
# Sortie : un tableau PASS / FAIL / WARN, et un code de retour non nul si au
# moins un contrôle est en FAIL (utilisable dans un pipeline CI ou un cron).
#
# Ce script ne modifie rien. Certains contrôles demandent sudo :
# sans sudo, `sshd -T` échoue et les contrôles SSH passent en FAIL.

set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"

# shellcheck source-path=SCRIPTDIR
# shellcheck source=lib/common.sh
source "$SCRIPT_DIR/lib/common.sh"

SSHD_DROPIN="/etc/ssh/sshd_config.d/50-hardening.conf"
PWQ_DROPIN="/etc/security/pwquality.conf.d/99-hardening.conf"
SYSCTL_DROPIN="/etc/sysctl.d/99-hardening.conf"
UMASK_PROFILE="/etc/profile.d/99-umask.sh"
AUDIT_RULES="/etc/audit/rules.d/99-hardening-lab.rules"

usage() {
    cat <<'EOF'
verify.sh – tableau PASS/FAIL du durcissement (lecture seule).

Usage : sudo ./scripts/verify.sh [OPTIONS]

Options :
  -n, --dry-run   Liste les contrôles sans les exécuter.
  -h, --help      Affiche cette aide.

Code de retour : 0 si tout est PASS (ou WARN), 1 si au moins un FAIL.
EOF
}

while (($# > 0)); do
    case "$1" in
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

pass_n=0
fail_n=0
warn_n=0

pass() {
    pass_n=$((pass_n + 1))
    print_result PASS "$1" "${2:-}"
}
fail() {
    fail_n=$((fail_n + 1))
    print_result FAIL "$1" "${2:-}"
}
warn() {
    warn_n=$((warn_n + 1))
    print_result WARN "$1" "${2:-}"
}

# --- Contrôles --------------------------------------------------------------

# check_sshd <paramètre> <valeur attendue en minuscules>
check_sshd() {
    local key="$1" expected="$2" actual
    if [[ -z "$SSHD_T" ]]; then
        fail "SSH : $key = $expected" "sshd -T indisponible (sudo requis ?)"
        return
    fi
    actual="$(printf '%s\n' "$SSHD_T" | awk -v k="$key" 'tolower($1) == k {print $2; exit}')"
    if [[ "$actual" == "$expected" ]]; then
        pass "SSH : $key = $expected" "valeur effective : $actual"
    else
        fail "SSH : $key = $expected" "valeur effective : ${actual:-absente}"
    fi
}

# check_file <chemin> <description>
check_exists() {
    if [[ -e "$1" ]]; then
        pass "$2" "$1"
    else
        fail "$2" "fichier absent : $1"
    fi
}

# check_sysctl <paramètre> <valeur attendue>
check_sysctl() {
    local key="$1" expected="$2" actual
    actual="$(sysctl -n "$key" 2>/dev/null || echo "indisponible")"
    if [[ "$actual" == "$expected" ]]; then
        pass "noyau : $key = $expected" "valeur : $actual"
    else
        fail "noyau : $key = $expected" "valeur : $actual"
    fi
}

# check_perm <fichier> <permission octale attendue>
check_perm() {
    local file="$1" expected="$2" actual
    if [[ ! -e "$file" ]]; then
        warn "Permissions : $file" "fichier absent"
        return
    fi
    actual="$(stat -c '%a' "$file")"
    if [[ "$((8#$actual))" -eq "$((8#$expected))" ]]; then
        pass "Permissions : $file = $expected" "valeur : $actual"
    else
        fail "Permissions : $file = $expected" "valeur : $actual"
    fi
}

if ((DRY_RUN)); then
    cat >&2 <<'EOF'
[DRY-RUN] Contrôles qui seraient exécutés :
  - SSH : PermitRootLogin, PasswordAuthentication, PubkeyAuthentication,
          MaxAuthTries, X11Forwarding, LoginGraceTime (via sshd -T)
  - sshd -t (syntaxe de la configuration)
  - présence des drop-ins pwquality, sysctl, umask, auditd
  - PASS_MAX_DAYS dans /etc/login.defs
  - firewalld : état, zone par défaut, services autorisés, règle riche SSH
  - noyau : rp_filter, accept_redirects, send_redirects, tcp_syncookies,
            dmesg_restrict, kptr_restrict
  - SELinux : mode Enforcing
  - permissions : /etc/shadow, /etc/sudoers
EOF
    exit 0
fi

log_step "Vérification du durcissement"
log_info "Machine : $(uname -n) – $(cat /etc/fedora-release 2>/dev/null || uname -sr)"

SSHD_T="$(sshd -T 2>/dev/null || true)"
if [[ -z "$SSHD_T" ]]; then
    warn "sshd -T n'a rien renvoyé" "lance avec sudo pour un résultat fiable"
fi

printf '\n%-4s | %-58s | %s\n' "ÉTAT" "CONTRÔLE" "DÉTAIL" >&2
printf '%s\n' "$(printf '%.0s-' {1..100})" >&2

# 1. SSH
check_sshd permitrootlogin no
check_sshd pubkeyauthentication yes
check_sshd maxauthtries 3
check_sshd x11forwarding no
check_sshd logingracetime 30
check_sshd passwordauthentication no

if subnet_out="$(sshd -t 2>&1)"; then
    pass "SSH : configuration valide (sshd -t)" "aucune erreur"
else
    fail "SSH : configuration valide (sshd -t)" "$subnet_out"
fi

# 2. Fichiers de configuration
check_exists "$SSHD_DROPIN" "Drop-in SSH présent"
check_exists "$PWQ_DROPIN" "Politique pwquality présente"
check_exists "$SYSCTL_DROPIN" "Drop-in sysctl présent"
check_exists "$UMASK_PROFILE" "Profil umask présent"
check_exists "$AUDIT_RULES" "Règles auditd présentes"

# 3. Durée de vie des mots de passe
max_days="$(awk '$1 == "PASS_MAX_DAYS" {print $2; exit}' /etc/login.defs 2>/dev/null || echo n/a)"
if [[ "$max_days" =~ ^[0-9]+$ ]] && ((max_days <= 90)); then
    pass "Mots de passe : PASS_MAX_DAYS <= 90" "valeur : $max_days"
else
    fail "Mots de passe : PASS_MAX_DAYS <= 90" "valeur : ${max_days:-absente}"
fi

# 4. Pare-feu
if firewall-cmd --state >/dev/null 2>&1; then
    pass "Pare-feu : firewalld actif" "$(firewall-cmd --version)"

    default_zone="$(firewall-cmd --get-default-zone)"
    if [[ "$default_zone" == "public" ]]; then
        pass "Pare-feu : zone par défaut explicite" "public"
    else
        warn "Pare-feu : zone par défaut" "$default_zone (attendu : public)"
    fi

    ssh_rule='rule service name="ssh" limit value="4/m" accept'
    if firewall-cmd --zone="$default_zone" --query-rich-rule="$ssh_rule" >/dev/null 2>&1; then
        pass "Pare-feu : limite de débit SSH active" "$ssh_rule"
    else
        fail "Pare-feu : limite de débit SSH active" "$ssh_rule"
    fi

    allowed="$(firewall-cmd --zone="$default_zone" --list-all | awk '/^  services:/ {sub(/^  services: */, ""); print}')"
    if [[ -z "$allowed" || "$allowed" == "ssh" ]]; then
        pass "Pare-feu : aucun service superflu" "services : ${allowed:-aucun (règle riche)}"
    else
        fail "Pare-feu : aucun service superflu" "services : $allowed"
    fi
else
    fail "Pare-feu : firewalld actif" "firewalld n'est pas démarré"
fi

# 5. Noyau
check_sysctl net.ipv4.conf.all.rp_filter 1
check_sysctl net.ipv4.conf.all.accept_redirects 0
check_sysctl net.ipv4.conf.all.send_redirects 0
check_sysctl net.ipv4.tcp_syncookies 1
check_sysctl kernel.dmesg_restrict 1
check_sysctl kernel.kptr_restrict 1

# 6. SELinux
if command -v getenforce >/dev/null 2>&1; then
    if [[ "$(getenforce)" == "Enforcing" ]]; then
        pass "SELinux : mode Enforcing" "getenforce = Enforcing"
    else
        fail "SELinux : mode Enforcing" "getenforce = $(getenforce)"
    fi
else
    warn "SELinux : mode Enforcing" "getenforce absent"
fi

# 7. Permissions
check_perm /etc/shadow 0
check_perm /etc/sudoers 440

# --- Résumé ----------------------------------------------------------------
printf '%s\n' "$(printf '%.0s-' {1..100})" >&2
printf 'Résumé : %d PASS, %d FAIL, %d WARN\n' "$pass_n" "$fail_n" "$warn_n" >&2

if ((fail_n > 0)); then
    log_error "Vérification en échec : $fail_n contrôle(s) FAIL."
    exit 1
fi

log_info "Vérification réussie."
exit 0
