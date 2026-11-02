# Modèle de menace (version courte)

Ce document répond à une seule question : **quel risque chaque mesure réduit-il ?**
Le périmètre est une machine Fedora de laboratoire, exposée sur un réseau local,
avec un service SSH actif. Ce n'est pas un modèle de menace complet d'entreprise.

## Hypothèses

- La machine est une VM de lab, joignable uniquement depuis le réseau local du lab.
- L'attaquant est simulé : il part du réseau local, sans accès physique.
- Les données à protéger sont les comptes locaux, la configuration du système et
  l'historique des connexions.
- Ce qui n'est **pas** couvert : attaque physique, firmware/UEFI, hyperviseur,
  compromission de la chaîne de build, ingénierie sociale.

## Risques et mesures

| Risque | Scénario concret | Mesure du lab | Fichier / script |
|---|---|---|---|
| Deviner un mot de passe SSH | Essais massifs sur le port 22 | Clés ed25519, `PasswordAuthentication no`, `MaxAuthTries 3` | `scripts/10-ssh.sh` |
| Vol de session SSH | Rebond depuis un compte root distant | `PermitRootLogin no`, `AllowUsers` | `scripts/10-ssh.sh` |
| Mot de passe faible ou éternel | Compte de service jamais changé | `pwquality` (12 car., 3 familles), `chage` 90 jours | `scripts/20-accounts.sh` |
| Escalade de privilèges | `sudo` donné à un groupe non prévu, `NOPASSWD` oublié | Contrôle en lecture seule de `/etc/sudoers*` | `scripts/20-accounts.sh` |
| Fichiers sensibles lisibles | `/etc/shadow` en 0644 | Contrôle et correction des permissions | `scripts/20-accounts.sh --apply` |
| Service exposé inutile | `avahi`, `cups`, `rpcbind` ouverts sans raison | Désactivation ciblée et justifiée | `scripts/40-services-kernel.sh` |
| Rebond réseau | Machine utilisée comme relais | `rp_filter`, `accept_redirects=0`, `send_redirects=0` | `scripts/40-services-kernel.sh` |
| Déni de service TCP | Saturation de la file de connexions | `tcp_syncookies=1` | `scripts/40-services-kernel.sh` |
| Fuite d'information noyau | `dmesg` lisible par tous | `kernel.dmesg_restrict=1`, `kptr_restrict=1` | `scripts/40-services-kernel.sh` |
| Brute force persistant | Attaque répétée sur plusieurs jours | `fail2ban` (bannissement via firewalld) | `scripts/50-auditd-fail2ban.sh` |
| Absence de traces | Modification de `/etc/passwd` sans preuve | Règles `auditd` avec clés de recherche | `scripts/50-auditd-fail2ban.sh` |
| Contournement de SELinux | Passage en `permissive` « pour que ça marche » | Contrôle `Enforcing`, jamais désactivé | `scripts/40-services-kernel.sh`, `verify.sh` |
| Verrouillage par erreur | `PasswordAuthentication no` sans clé en place | Garde-fou : refus si `authorized_keys` vide | `scripts/10-ssh.sh` |

## Ce que ce lab ne protège pas

- Un attaquant avec un accès `root` déjà obtenu (il peut tout modifier).
- Une modification faite **avant** le durcissement : seule la comparaison
  `evidence/before` / `evidence/after` peut la révéler.
- Les erreurs applicatives : le durcissement système ne remplace pas la
  sécurisation d'un service web ou d'une base de données.

## Démarche

1. Mesurer avant (`audit/baseline.sh`).
2. Durcir une brique à la fois, avec sauvegarde et retour arrière possible.
3. Mesurer après (`audit/baseline.sh --output evidence/after`).
4. Vérifier par des contrôles automatiques (`scripts/verify.sh`) et par des tests
   manuels (connexion SSH réelle, `nmap` depuis l'hôte vers **ma** VM).
