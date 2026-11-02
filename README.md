# linux-hardening-lab-fedora

[![Système](https://img.shields.io/badge/système-Fedora%2044-51A2DA)](https://fedoraproject.org/)
[![Shell](https://img.shields.io/badge/scripts-Bash%205-4EAA25)](https://www.gnu.org/software/bash/)
[![shellcheck](https://img.shields.io/badge/shellcheck-passing-brightgreen)](https://www.shellcheck.net/)
[![Licence](https://img.shields.io/badge/licence-MIT-blue)](LICENSE)

Durcissement d'un système Linux Fedora : SSH, comptes, permissions, pare-feu,
noyau, traçabilité. Avant/après mesuré et vérifié par des contrôles automatiques.

> **Ce dépôt est un laboratoire.** Les scripts sont faits pour une VM de test avec
> un instantané (snapshot) pris avant de commencer. N'applique pas ceci directement
> sur une machine qui compte.

---

## Objectif

Réduire la surface d'attaque d'une machine Fedora de façon **mesurable** :

1. relever l'état initial (`evidence/before`) ;
2. appliquer des mesures de durcissement, une brique à la fois, avec sauvegarde ;
3. relever l'état final (`evidence/after`) et **vérifier** que chaque mesure
   est réellement active (`scripts/verify.sh`, tableau PASS/FAIL) ;
4. garder une trace des tests manuels (connexion SSH par clé, `nmap`).

## Contexte

Projet de portfolio (technicien informatique junior en reconversion vers la
cybersécurité). Objectif : montrer une démarche d'administration sécurisée,
pas seulement l'application de recettes. L'environnement cible est une VM Fedora
de lab, sur un réseau local privé, administrée à distance en SSH.

## Prérequis et outils

| Outil | Version utilisée (testé) | Rôle |
|---|---|---|
| Fedora Linux Workstation | 44 (`/etc/fedora-release`) | système cible |
| Bash | 5.x | scripts |
| OpenSSH | `OpenSSH_10.2p1` (paquet `openssh-server-10.2p1-16.fc44`) | accès distant durci |
| firewalld | 2.4.4 | pare-feu |
| shellcheck | 0.11.0 | analyse statique des scripts |
| Lynis | optionnel (`dnf install lynis`) | score de durcissement avant/après |
| audit / fail2ban | optionnels (`dnf install audit fail2ban`) | traçabilité et bannissement |

Avant de commencer : **snapshot de la VM**, accès console (pas seulement SSH) et
une clé SSH déjà générée sur ton poste client.

## Architecture

```text
poste client (ton PC)                      VM Fedora de lab
+----------------------+                   +---------------------------+
| clé ed25519 privée   |  --- SSH 22 --->  | sshd (clé only, no root)  |
| nmap (test de port)  |                   | firewalld (zone public)   |
+----------------------+                   | SELinux enforcing         |
                                           | auditd + fail2ban         |
                                           +---------------------------+
                                                   ^
                                                   | scripts (sudo)
                                           +---------------------------+
                                           | ce dépôt (git)            |
                                           +---------------------------+
```

Détail du risque couvert par chaque mesure : [`docs/threat-model.md`](docs/threat-model.md).

## Arborescence

```text
linux-hardening-lab-fedora/
├── audit/baseline.sh              # relevé avant/après (lecture seule)
├── scripts/
│   ├── lib/common.sh              # journal, dry-run, sauvegardes, garde-fous
│   ├── 10-ssh.sh                  # SSH : clés, drop-in, reload sûr
│   ├── 20-accounts.sh             # mots de passe, comptes, permissions, umask
│   ├── 30-firewall.sh             # firewalld : zone, SSH seul, limite de débit
│   ├── 40-services-kernel.sh      # services inutiles, sysctl, SELinux
│   ├── 50-auditd-fail2ban.sh      # règles auditd + jail fail2ban
│   ├── verify.sh                  # tableau PASS/FAIL, code retour 1 si échec
│   └── rollback.sh                # restauration des sauvegardes
├── docs/
│   ├── threat-model.md            # quel risque, quelle mesure
│   ├── services.md                # liste justifiée des services désactivés
│   └── mapping.md                 # correspondance ANSSI-BP-028 v2.0
├── evidence/                      # preuves (voir evidence/README.md)
└── README.md
```

## Étapes pas à pas

### 0. Garde-fous communs

Tous les scripts qui modifient le système :

- exigent `LAB_CONFIRM=yes` (sinon ils refusent de s'exécuter) ;
- acceptent `--dry-run` (simulation) et `--help` ;
- écrivent un journal dans `/var/log/hardening-lab.log` ;
- sauvegardent chaque fichier modifié dans `/var/backups/hardening-lab/<date>/`.

```bash
git clone <URL_DE_TON_DEPOT> && cd linux-hardening-lab-fedora
chmod +x audit/*.sh scripts/*.sh
./scripts/verify.sh --dry-run      # ne modifie rien
```

### 1. Audit initial

```bash
sudo ./audit/baseline.sh                    # -> evidence/before/
sudo ./audit/baseline.sh --output /tmp/check # pour comparer
```

Contrôles : version de l'OS, utilisateurs avec shell, ports en écoute
(`ss -tulpn`), services actifs, SELinux (`sestatus`), firewalld, configuration
SSH effective (`sshd -T`), fichiers SUID/SGID, fichiers `world-writable`,
permissions de `/etc/passwd`, `/etc/shadow`, `/etc/sudoers`, score Lynis si présent.

### 2. SSH

```bash
# 1) Simulation : rien n'est écrit
sudo ./scripts/10-ssh.sh --dry-run

# 2) Application (mot de passe encore autorisé : c'est volontaire)
export LAB_CONFIRM=yes
sudo -E ./scripts/10-ssh.sh
```

Le script écrit `/etc/ssh/sshd_config.d/50-hardening.conf` :
`PermitRootLogin no`, `PubkeyAuthentication yes`, `MaxAuthTries 3`,
`LoginGraceTime 30`, `X11Forwarding no`, `AllowUsers <ton_utilisateur>`,
`ClientAliveInterval 300`, `ClientAliveCountMax 2`.
Il vérifie que `sshd_config` contient bien `Include /etc/ssh/sshd_config.d/*.conf`
(sinon il l'ajoute en tête, car sshd garde la **première** valeur rencontrée),
lance `sshd -t` **avant** `systemctl reload sshd`, et restaure la sauvegarde si
le test échoue.

Puis, dans un **second terminal** :

```bash
ssh -i ~/.ssh/id_ed25519 TON_UTILISATEUR@ADRESSE-DE-LA-VM
```

Si (et seulement si) cette connexion par clé fonctionne :

```bash
sudo -E ./scripts/10-ssh.sh --disable-password
```

### 3. Comptes, mots de passe, permissions

```bash
sudo -E ./scripts/20-accounts.sh              # rapport
sudo -E ./scripts/20-accounts.sh --apply      # corrige les permissions anormales
sudo -E ./scripts/20-accounts.sh --list       # liste des comptes (lecture seule)
sudo -E ./scripts/20-accounts.sh --lock vieux_compte
```

`pwquality` : 12 caractères minimum, 3 familles de caractères, `maxrepeat=3`,
`difok=3`, `dictcheck`. `chage` : 90 jours max, 1 jour min, préavis 14 jours,
inactivité 30 jours. `umask 027` pour les nouvelles sessions. Les droits `sudo`
sont **contrôlés mais jamais modifiés** : une erreur dans `sudoers` peut coûter
l'accès à `sudo`.

### 4. Pare-feu

```bash
sudo -E ./scripts/30-firewall.sh --no-remove     # voir sans changer
sudo -E ./scripts/30-firewall.sh                 # appliquer
```

Zone par défaut explicite (`public`), service `ssh` remplacé par une règle riche
qui limite à 4 connexions par minute, journalisation des paquets refusés
(`--set-log-denied=all`), `--permanent` puis `--reload`.
Ordre anti-verrouillage : la règle riche est ajoutée **et vérifiée** avant de
retirer le service `ssh` ; en cas d'échec, le service est remis en place.

Test depuis **ton poste**, uniquement vers **ta VM** :

```bash
nmap -sT -p 22,80,443 ADRESSE-DE-LA-VM
```

### 5. Services et noyau

```bash
sudo -E ./scripts/40-services-kernel.sh --list-only
sudo -E ./scripts/40-services-kernel.sh
```

Désactive `avahi`, `cups`, `bluetooth`, `rpcbind`, `nfs-server`, `postfix`,
`vsftpd`, `telnet.socket` — chaque ligne est justifiée dans
[`docs/services.md`](docs/services.md), et un service absent est simplement
ignoré. Écrit `/etc/sysctl.d/99-hardening.conf` (chaque paramètre y est commenté)
puis `sysctl --system`. Vérifie que SELinux est en `Enforcing` sans jamais
le modifier.

### 6. Bonus : auditd + fail2ban

```bash
sudo dnf install audit fail2ban
sudo -E ./scripts/50-auditd-fail2ban.sh
```

Règles `auditd` sur `/etc/passwd`, `/etc/shadow`, `/etc/group`, `/etc/gshadow`,
`/etc/sudoers*`, `/etc/ssh/sshd_config*` et l'exécution de `useradd`/`usermod`/`passwd`.
`jail.local` aligné sur firewalld (`banaction = firewallcmd-ipset`,
`backend = systemd`), avec test `fail2ban-client -t` avant démarrage.

### 7. Vérification et retour arrière

```bash
sudo ./scripts/verify.sh                                    # tableau PASS/FAIL
sudo ./audit/baseline.sh --output evidence/after             # relevé après
sudo ./scripts/rollback.sh --list                            # sauvegardes
sudo -E ./scripts/rollback.sh                                # restaurer la dernière
```

## Vérification et résultats

```bash
$ sudo ./scripts/verify.sh
ÉTAT | CONTRÔLE                                                  | DÉTAIL
PASS | SSH : permitrootlogin = no                                | valeur effective : no
PASS | SSH : pubkeyauthentication = yes                          | valeur effective : yes
PASS | SSH : maxauthtries = 3                                    | valeur effective : 3
PASS | SSH : x11forwarding = no                                  | valeur effective : no
PASS | SSH : passwordauthentication = no                         | valeur effective : no
PASS | SSH : configuration valide (sshd -t)                      | aucune erreur
PASS | Pare-feu : firewalld actif                                | 2.4.4
PASS | Pare-feu : limite de débit SSH active                     | rule service name="ssh" limit value="4/m" accept
PASS | noyau : net.ipv4.conf.all.rp_filter = 1                   | valeur : 1
PASS | SELinux : mode Enforcing                                  | getenforce = Enforcing
Résumé : 26 PASS, 0 FAIL, 0 WARN
```

> La sortie ci-dessus est un **exemple de référence**. Remplace-la par la sortie
> réelle de ta VM (voir [`evidence/README.md`](evidence/README.md)) : c'est la
> preuve attendue par un recruteur.

## Difficultés rencontrées et solutions

| Difficulté | Cause | Solution retenue |
|---|---|---|
| Se couper l'accès SSH en coupant le mot de passe | Une clé non testée peut ne pas être acceptée | Le script **refuse** `PasswordAuthentication no` si `authorized_keys` est vide, et rappelle la méthode « second terminal » |
| `sshd_config.d/*.conf` ignoré | sshd garde la **première** valeur lue : sans `Include` en tête, les drop-ins ne s'appliquent pas | Vérification de l'`Include`, ajout en tête de fichier si absent, `sshd -t` avant `reload` |
| `shutdown`/`restart` de sshd risqué | Un `restart` coupe les sessions en cours | `systemctl reload sshd` uniquement, jamais `restart` |
| Verrouillage possible par firewalld | Retirer le service `ssh` sans règle de remplacement ferme le port 22 | Règle riche ajoutée **et vérifiée** d'abord ; service remis en place si le contrôle échoue |
| Liste de services « à désactiver » | Une liste générique casse la machine | Liste courte, chaque entrée justifiée dans `docs/services.md`, services statiques ignorés |
| `# shellcheck source=` | Le chemin est résolu depuis le répertoire courant, pas le fichier | Directive `# shellcheck source-path=SCRIPTDIR` |
| Redirection et `set -e` | `: >> fichier` sans droit affiche une erreur non capturée | Groupe `{ ...; } 2>/dev/null` explicite dans `lib/common.sh` |

## Compétences démontrées

- **Administration Linux** : systemd, `sshd`, `firewalld`, `selinux`, `sysctl`, `pam_pwquality`, `chage`.
- **Écriture de scripts** : Bash `set -euo pipefail`, `--dry-run`, journalisation, idempotence, garde-fous, analyse `shellcheck` sans avertissement.
- **Sécurité défensive** : moindre privilège, réduction de surface d'attaque, défense en profondeur, sauvegarde avant modification, retour arrière.
- **Méthode** : mesure avant/après, preuve par sortie de commande, correspondance avec un référentiel officiel (ANSSI-BP-028 v2.0).
- **Documentation technique** : mode d'emploi reproductible, limites assumées, commandes vérifiables.

## Limites et améliorations

- Pas de test unitaire des scripts (pas encore d'infrastructure `bats`/`shellspec`) : validate via `shellcheck` et les `--dry-run`.
- Pas de configuration « Infra as Code » : ces scripts pourraient devenir un rôle Ansible (`ansible-role-anssi` existe en amont).
- Pas de gestion des mises à jour (`dnf-automatic`) ni du chiffrement disque : ce sont des choix d'installation.
- La limite de débit SSH (4/min) peut gêner des reconnexions rapprochées : à ajuster selon l'usage.
- Le mapping ANSSI reste au niveau du thème : une vérification numéro par numéro avec le PDF serait un vrai plus.
- Améliorations possibles : `oscap` avec un profil `anssi_bp28_*`, `bats` pour les tests des scripts, `inotify`/`auditd` vers un collecteur central.

## Ressources

- ANSSI, *Recommandations de configuration d'un système GNU/Linux*, ANSSI-BP-028 v2.0 — <https://cyber.gouv.fr/publications/recommandations-de-securite-relatives-un-systeme-gnulinux>
- `man sshd_config`, `man sshd`, `man firewall-cmd`, `man firewalld.richlanguage`, `man sysctl.d`, `man pwquality.conf`, `man chage`, `man auditctl`, `man fail2ban`, `man journalctl`
- Fedora Docs — <https://docs.fedoraproject.org/>
- ShellCheck — <https://www.shellcheck.net/> (wiki des codes SCxxxx)
- Lynis (audit de durcissement) — <https://cisofy.com/lynis/>
- OpenSCAP / ComplianceAsCode (profils ANSSI) — <https://www.open-scap.org/>

## Ce que j'ai appris

`À COMPLÉTER PAR ANALTINO`
