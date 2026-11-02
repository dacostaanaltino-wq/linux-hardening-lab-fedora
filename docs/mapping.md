# Correspondance avec le guide ANSSI-BP-028 (v2.0)

Guide de référence : **ANSSI-BP-028, « Recommandations de configuration d'un
système GNU/Linux », version 2.0**, publié par l'ANSSI (PDF daté du 03/10/2022).
Page officielle : <https://cyber.gouv.fr/publications/recommandations-de-securite-relatives-un-systeme-gnulinux>

## Avertissement de méthode

Le guide numérote ses recommandations et utilise quatre niveaux de durcissement
(minimal, intermédiaire, renforcé, élevé). **Les numéros exacts de recommandations
ne sont volontairement pas recopiés dans ce tableau** : ils ont changé entre la
version 1 et la version 2, et une erreur de numérotation dans un portfolio serait
plus grave que l'absence de numéro. Le tableau donne le **thème** ; ouvre le PDF
et cherche le thème pour retrouver le numéro et le niveau.

Ce lab visait globalement le **niveau minimal**, avec quelques mesures que le
guide place plus haut (journalisation `auditd`, durcissement réseau).

## Tableau de correspondance

| Thème du guide ANSSI-BP-028 | Mesure appliquée dans ce lab | Où | Statut |
|---|---|---|---|
| Mots de passe : robustesse | `pwquality` : 12 caractères, 3 familles, `maxrepeat=3`, `difok=3`, `dictcheck` | `scripts/20-accounts.sh` | Appliqué, vérifié |
| Mots de passe : durée de vie | `PASS_MAX_DAYS 90`, `PASS_MIN_DAYS 1`, `chage --inactive 30` | `scripts/20-accounts.sh` | Appliqué, vérifié |
| Comptes : moindre privilège | Contrôle que seul `%wheel` a `sudo`, alerte sur `NOPASSWD` | `scripts/20-accounts.sh` | Contrôlé (non modifié) |
| Comptes : comptes inutilisés | `usermod -L` + expiration (`--lock`) | `scripts/20-accounts.sh` | Manuel, sur demande |
| Droits des fichiers sensibles | `/etc/shadow` 0000, `/etc/sudoers` 0440, `umask 027` | `scripts/20-accounts.sh` | Appliqué, vérifié |
| Accès distant : SSH par clé | Clé `ed25519`, `PasswordAuthentication no`, `PubkeyAuthentication yes` | `scripts/10-ssh.sh` | Appliqué (après test de clé) |
| Accès distant : restrictions | `PermitRootLogin no`, `AllowUsers`, `MaxAuthTries 3`, `LoginGraceTime 30`, `X11Forwarding no` | `scripts/10-ssh.sh` | Appliqué, vérifié |
| Filtrage réseau local | `firewalld` : zone explicite, service `ssh` seul, journalisation des refus | `scripts/30-firewall.sh` | Appliqué, vérifié |
| Filtrage réseau : limitation | Limite de débit des connexions SSH (règle riche firewalld) | `scripts/30-firewall.sh` | Appliqué, vérifié |
| Noyau : anti-usurpation et redirections | `rp_filter`, `accept_redirects=0`, `send_redirects=0`, `accept_source_route=0` | `scripts/40-services-kernel.sh` | Appliqué, vérifié |
| Noyau : protection mémoire | `kernel.dmesg_restrict`, `kernel.kptr_restrict` | `scripts/40-services-kernel.sh` | Appliqué, vérifié |
| Noyau : `fs.protected_*` | `protected_hardlinks`, `protected_symlinks` | `scripts/40-services-kernel.sh` | Appliqué, vérifié |
| Noyau : SYN cookies | `net.ipv4.tcp_syncookies = 1` | `scripts/40-services-kernel.sh` | Appliqué, vérifié |
| Réduction de la surface d'attaque | Désactivation des services inutiles (liste justifiée) | `scripts/40-services-kernel.sh`, `docs/services.md` | Appliqué, partiel |
| Contrôle d'accès obligatoire | SELinux **Enforcing**, jamais désactivé | `scripts/40-services-kernel.sh`, `verify.sh` | Vérifié |
| Journalisation des événements | `auditd` : `/etc/passwd`, `/etc/shadow`, `/etc/sudoers.d`, `sshd_config` | `scripts/50-auditd-fail2ban.sh` | Appliqué si `audit` installé |
| Traçabilité des accès | `fail2ban` + `journald` (`backend = systemd`) | `scripts/50-auditd-fail2ban.sh` | Appliqué si `fail2ban` installé |
| Mises à jour de sécurité | Hors périmètre de ces scripts (`dnf upgrade --security`) | — | Non traité (voir « Limites ») |
| Chiffrement du disque | LUKS à l'installation | — | Non traité (à faire à l'installation) |
| Partitionnement | `/tmp`, `/var`, `/home` séparés | — | Non traité (à faire à l'installation) |

## Points du guide volontairement non appliqués

- **`-e 2` sur les règles auditd** (verrouillage définitif) : le guide le
  recommande pour un serveur en production, mais il oblige à redémarrer pour
  changer une règle. Inadapté à un lab itératif.
- **Bannière légale (`/etc/issue`) détaillée** : mentionnée dans le README,
  non automatisée, car le contenu dépend de l'organisation.
- **Montage de `/tmp` en `noexec,nosuid,nodev`** : à faire dans `/etc/fstab`,
  risque de casser des outils si on le fait à l'aveugle sur une machine de travail.
  Non automatisé : décision manuelle, documentée comme amélioration.

## Vérifier soi-même

```bash
# Le guide est un PDF : ouvre-le et cherche le thème dans le sommaire.
sudo ./scripts/verify.sh        # tableau PASS/FAIL
```

Une correspondance « officielle » complète existe aussi sous forme de profils
SCAP/OpenSCAP (`anssi_bp28_minimal`, `anssi_bp28_intermediary`…) maintenus par
le projet ComplianceAsCode : c'est la référence si tu veux automatiser l'audit
avec `oscap`.
