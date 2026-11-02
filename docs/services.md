# Services désactivés : liste justifiée

Chaque service de cette liste est désactivé par `scripts/40-services-kernel.sh`.
La règle est simple : **on ne désactive pas « à l'aveugle »**. Si un service est
utile dans ton contexte, retire-le de la liste `UNUSED_SERVICES` dans le script.

| Service | Ce qu'il fait | Pourquoi le désactiver ici | Ce que tu perds |
|---|---|---|---|
| `avahi-daemon.service` | Découverte de services en mDNS (imprimantes, partages) | Écoute sur le réseau local et diffuse le nom de la machine | La découverte automatique des imprimantes |
| `cups.service` | Serveur d'impression | Une VM de serveur n'imprime pas ; `cups` écoute sur le port 631 | L'impression locale |
| `bluetooth.service` | Pile Bluetooth | Un serveur n'a pas de Bluetooth ; surface d'attaque sans usage | Le Bluetooth, évidemment |
| `rpcbind.service`, `rpcbind.socket` | Annuaire des services RPC (NFS) | Inutile sans NFS ; écoute sur le port 111 | NFS côté client |
| `nfs-server.service` | Serveur de fichiers NFS | Pas de partage NFS dans ce lab | Le partage NFS |
| `postfix.service` | Serveur SMTP local | Souvent installé par défaut, écoute en local ; un lab n'envoie pas de courriel | L'envoi de courriel local (cron, logwatch) |
| `vsftpd.service` | Serveur FTP | FTP est en clair (mot de passe lisible sur le réseau) ; inutile ici | Le service FTP |
| `telnet.socket` | Serveur Telnet | Protocole en clair, remplacé par SSH | Telnet |

## Services qui ne doivent JAMAIS être désactivés ici

| Service | Raison |
|---|---|
| `sshd.service` | Sinon plus d'accès distant (le lab repose dessus) |
| `firewalld.service` | Sinon plus de pare-feu |
| `auditd.service` | Sinon plus de traces d'audit |
| `chronyd.service` | Sans heure juste, les journaux et les certificats sont incohérents |
| `systemd-*` | Composants de base du système |

## Ce que fait exactement le script

```text
systemctl stop <service>        # arrêt immédiat
systemctl disable --now <svc>   # ne redémarrera plus au boot
```

Un service **statique** (`static`) est laissé tel quel : il ne se lance pas seul,
il est démarré par un socket ou par un autre service (`systemctl is-enabled`
renvoie `static`). Le désactiver n'aurait pas de sens, et le masquer pourrait
casser son parent.

## Vérification

```bash
# Ne doit plus rien afficher (hors services non installés)
systemctl is-active avahi-daemon cups bluetooth rpcbind postfix vsftpd telnet.socket

# Liste de ce qui reste activé
systemctl list-unit-files --state=enabled --no-pager
```

Pour annuler une désactivation :

```bash
sudo systemctl enable --now cups.service
```
