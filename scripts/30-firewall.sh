#!/usr/bin/env bash
# scripts/30-firewall.sh – pare-feu firewalld : zone explicite, SSH seul, anti-bruteforce.
#
# Ce que fait le script :
#   1. vérifie que firewalld est actif (et l'active si besoin) ;
#   2. fixe explicitement la zone par défaut ;
#   3. garde le service ssh, retire les services inutiles APRÈS vérification ;
#   4. limite le débit des connexions SSH avec une règle « riche » firewalld ;
#   5. journalise les paquets refusés ;
#   6. applique en --permanent puis recharge, et vérifie le résultat.
#
# Ordre important (anti-verrouillage) : la règle riche SSH est ajoutée et
# vérifiée AVANT de retirer le service « ssh » de la zone. Si la règle
# échoue, le service ssh est toujours là et l'accès reste possible.

set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"

# shellcheck source-path=SCRIPTDIR
# shellcheck source=lib/common.sh
source "$SCRIPT_DIR/lib/common.sh"

ZONE="public"
SSH_LIMIT="4/m"
KEEP_SERVICES="ssh"
REMOVE_EXTRA=1

usage() {
    cat <<'EOF'
30-firewall.sh – firewalld : zone par défaut, SSH seul, limite de débit SSH.

Usage : sudo ./scripts/30-firewall.sh [OPTIONS]

Options :
  -z, --zone NAME       Zone firewalld à configurer (défaut : public).
      --ssh-limit RATE  Limite de connexions SSH (défaut : 4/m = 4 par minute).
      --keep SVCS       Services à conserver, séparés par des virgules
                        (défaut : ssh). Les autres services de la zone sont retirés.
      --no-remove       Ne retire aucun service : affiche seulement la liste.
  -n, --dry-run         Affiche les actions sans rien modifier.
  -h, --help            Affiche cette aide.

Après le script, depuis TON poste (jamais contre un tiers) :
  nmap -sT -p 22,80,443 ADRESSE-DE-LA-VM
  ssh -v UTILISATEUR@ADRESSE-DE-LA-VM    # doit toujours fonctionner

Le script exige LAB_CONFIRM=yes pour modifier le système.
EOF
}

while (($# > 0)); do
    case "$1" in
        -z | --zone)
            [[ $# -ge 2 ]] || die "L'option $1 demande un argument."
            ZONE="$2"
            shift 2
            ;;
        --ssh-limit)
            [[ $# -ge 2 ]] || die "L'option $1 demande un argument."
            SSH_LIMIT="$2"
            shift 2
            ;;
        --keep)
            [[ $# -ge 2 ]] || die "L'option $1 demande un argument."
            KEEP_SERVICES="$2"
            shift 2
            ;;
        --no-remove)
            REMOVE_EXTRA=0
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
require_cmd firewall-cmd

log_step "Pare-feu firewalld (zone=$ZONE, dry-run=$DRY_RUN)"

# ---------------------------------------------------------------------------
# 1. firewalld actif
# ---------------------------------------------------------------------------
if firewall-cmd --state >/dev/null 2>&1; then
    log_info "firewalld est actif : $(firewall-cmd --version)"
else
    log_warn "firewalld n'est pas actif."
    run systemctl enable --now firewalld
    if ((!DRY_RUN)) && ! firewall-cmd --state >/dev/null 2>&1; then
        die "Impossible de démarrer firewalld. Vérifie : systemctl status firewalld"
    fi
fi

if ! firewall-cmd --get-zones | tr ' ' '\n' | grep -qx "$ZONE"; then
    die "Zone inconnue : $ZONE (zones disponibles : $(firewall-cmd --get-zones))"
fi

# ---------------------------------------------------------------------------
# 2. Zone par défaut explicite
# ---------------------------------------------------------------------------
current_default="$(firewall-cmd --get-default-zone)"
if [[ "$current_default" == "$ZONE" ]]; then
    log_info "Zone par défaut déjà réglée sur $ZONE"
else
    log_info "Zone par défaut : $current_default -> $ZONE"
    run firewall-cmd --set-default-zone="$ZONE"
fi

# ---------------------------------------------------------------------------
# 3. Services de la zone
# ---------------------------------------------------------------------------
mapfile -t services < <(firewall-cmd --zone="$ZONE" --list-services | tr ' ' '\n' | sed '/^$/d')
log_info "Services actuellement autorisés dans $ZONE : ${services[*]:-aucun}"

IFS=',' read -r -a keep_array <<<"$KEEP_SERVICES"
keep_has_ssh=0
for svc in "${keep_array[@]}"; do
    [[ "$svc" == "ssh" ]] && keep_has_ssh=1
done
((keep_has_ssh)) || die "Refus : le service ssh doit rester dans --keep (sinon perte d'accès)."

if ((DRY_RUN)); then
    for svc in "${services[@]}"; do
        keep=0
        for k in "${keep_array[@]}"; do [[ "$svc" == "$k" ]] && keep=1; done
        ((keep)) || log_info "[DRY-RUN] retirerait le service $svc de la zone $ZONE"
    done
else
    for svc in "${services[@]}"; do
        keep=0
        for k in "${keep_array[@]}"; do [[ "$svc" == "$k" ]] && keep=1; done
        if ((keep)); then
            log_info "Conservé : $svc"
        elif ((REMOVE_EXTRA)); then
            log_info "Retiré : $svc"
            run firewall-cmd --zone="$ZONE" --permanent --remove-service="$svc"
        else
            log_warn "Conservé (--no-remove) : $svc"
        fi
    done
fi

# ---------------------------------------------------------------------------
# 4. Limitation du débit SSH (règle riche firewalld)
# ---------------------------------------------------------------------------
# Syntaxe vérifiée dans firewalld.richlanguage(5) :
#   accept [limit value="rate/duration"]
# La règle autorise au plus N connexions par minute ; au-delà, le paquet
# tombe dans la politique par défaut de la zone (refus).
SSH_RULE="rule service name=\"ssh\" limit value=\"$SSH_LIMIT\" accept"

log_info "Règle SSH : $SSH_RULE"
if firewall-cmd --zone="$ZONE" --query-rich-rule="$SSH_RULE" >/dev/null 2>&1; then
    log_info "Règle déjà présente."
else
    run firewall-cmd --zone="$ZONE" --permanent --add-rich-rule="$SSH_RULE"
fi

# ---------------------------------------------------------------------------
# 5. Journalisation des paquets refusés + 6. application
# ---------------------------------------------------------------------------
log_info "Journalisation des refus (--set-log-denied=all)"
run firewall-cmd --set-log-denied=all

run firewall-cmd --reload

# ---------------------------------------------------------------------------
# Vérification
# ---------------------------------------------------------------------------
if ((DRY_RUN)); then
    log_info "[DRY-RUN] vérifierait : firewall-cmd --zone=$ZONE --list-all"
    log_step "Simulation terminée (aucune modification)"
    exit 0
fi

# La règle riche doit être active ET le service doit pouvoir être retiré.
if ! firewall-cmd --zone="$ZONE" --query-rich-rule="$SSH_RULE" >/dev/null 2>&1; then
    die "La règle riche SSH n'est pas active : le service ssh est conservé, accès intact.
Diagnostic : firewall-cmd --zone=$ZONE --list-all"
fi

# On retire le service ssh seulement une fois la règle riche confirmée active :
# sinon le port 22 serait fermé.
if firewall-cmd --zone="$ZONE" --list-services | tr ' ' '\n' | grep -qx ssh; then
    log_info "Service ssh encore présent : retrait (la règle riche le remplace)."
    run firewall-cmd --zone="$ZONE" --permanent --remove-service=ssh
    run firewall-cmd --reload
    if ! firewall-cmd --zone="$ZONE" --query-rich-rule="$SSH_RULE" >/dev/null 2>&1; then
        log_error "Perte de la règle après reload : restauration du service ssh."
        run firewall-cmd --zone="$ZONE" --permanent --add-service=ssh
        run firewall-cmd --reload
        die "Retour à l'état sécurité précédent (service ssh restauré)."
    fi
fi

log_step "État final de la zone $ZONE"
firewall-cmd --zone="$ZONE" --list-all | tee -a /dev/null

log_step "Étape pare-feu terminée"
log_info "Test depuis ton poste : nmap -sT -p 22,80,443 ADRESSE-DE-LA-VM"
log_info "Journaux des refus : sudo journalctl -k | grep -iE 'REJECT|DROP'"
log_info "Rappel : la limite de débit peut gêner des reconnexions rapides. Teste avant d'oublier."
