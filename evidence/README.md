# Evidence – mode d'emploi

Ce dossier contient les **preuves** : ce qui prouve qu'un contrôle a réellement
été exécuté sur ma VM. Une affirmation du README sans preuve ne vaut rien.

## Ce qui est généré automatiquement

```bash
sudo ./audit/baseline.sh                       # -> evidence/before/
sudo ./audit/baseline.sh --output evidence/after
```

Ces dossiers ne sont **pas publiés** (voir `.gitignore`) : ils contiennent le
hostname, les noms d'utilisateurs et les adresses IP locales de ma machine.

## Ce que je publie (nettoyé à la main)

| Fichier | Contenu | Comment le produire |
|---|---|---|
| `RESULTS.md` | tableau PASS/FAIL + tableau avant/après | copier-colle de `sudo ./scripts/verify.sh` et des fichiers `99-summary.txt` |
| `screenshots/*.png` | captures de la sortie des commandes clés | capture d'écran du terminal |
| `before/`, `after/` | **jamais publiés** | restent en local |

## Anonymisation avant publication

À vérifier avant chaque commit :

```bash
# Adresses IPv4 (remplacer par des IP de documentation 192.0.2.x / 198.51.100.x / 203.0.113.x)
git grep -nE "([0-9]{1,3}\.){3}[0-9]{1,3}"

# Secrets éventuels
git grep -niE "password|passwd|token|secret|BEGIN .*PRIVATE KEY"

# Nom de machine et nom d'utilisateur réels
git grep -ni "hostname\|$(whoami)"
```

Dans les captures d'écran : vérifier le prompt (le nom d'utilisateur y apparaît),
et flouter si nécessaire. Les adresses MAC et les e-mails doivent aussi être
retirés.

## Liste des captures à prendre

1. `01-fedora-version.png` – `cat /etc/fedora-release` + `uname -r`.
2. `02-avant-lynis.png` – score Lynis avant (`evidence/before/91-lynis.txt`).
3. `03-sshd-t.png` – `sudo sshd -T | grep -E 'permitrootlogin|passwordauth|maxauthtries'`.
4. `04-test-cle-ssh.png` – connexion par clé depuis un second terminal.
5. `05-firewalld.png` – `sudo firewall-cmd --list-all`.
6. `06-nmap.png` – `nmap -sT -p 22,80,443 <IP-de-ma-VM>` depuis mon poste.
7. `07-verify.png` – `sudo ./scripts/verify.sh` avec le tableau complet.
8. `08-apres-lynis.png` – score Lynis après.
9. `09-fail2ban.png` – `sudo fail2ban-client status sshd` après quelques échecs.

Rappel : le mot-clé `À COMPLÉTER PAR ANALTINO` dans le README signale la section
que je dois écrire moi-même.
