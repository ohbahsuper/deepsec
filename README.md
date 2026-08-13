# DeepSec

```text
██████╗ ███████╗███████╗██████╗ ███████╗███████╗ ██████╗
██╔══██╗██╔════╝██╔════╝██╔══██╗██╔════╝██╔════╝██╔════╝
██║  ██║█████╗  █████╗  ██████╔╝███████╗█████╗  ██║
██║  ██║██╔══╝  ██╔══╝  ██╔═══╝ ╚════██║██╔══╝  ██║
██████╔╝███████╗███████╗██║     ███████║███████╗╚██████╗
╚═════╝ ╚══════╝╚══════╝╚═╝     ╚══════╝╚══════╝ ╚═════╝
```

DeepSec est un outil Python compact d’observation de surface d’exposition et d’audit défensif. Il analyse uniquement des réponses publiques, sans exploiter les vulnérabilités ni modifier les données.

> [!DANGER]
> **Autorisation obligatoire** — DeepSec est destiné uniquement aux systèmes, domaines et applications que vous possédez ou pour lesquels vous disposez d’une autorisation explicite.

## Fonctionnalités

- résolution DNS, disponibilité HTTPS et inspection TLS/certificat ;
- headers de sécurité, cookies, CORS et redirections ;
- détection prudente de technologies et de versions explicitement exposées ;
- inspection limitée de JavaScript public, sans utilisation de secrets ;
- robots.txt, security.txt, fichiers sensibles courants et erreurs publiques ;
- rate limiting intégré, concurrence plafonnée et redirections limitées à HTTP(S) ;
- rapports terminal Rich, JSON SIEM/API et HTML.

## Installation

```bash
git clone https://github.com/ohbahsuper/deepsec.git
cd deepsec
python -m venv .venv

# Linux/macOS
source .venv/bin/activate

# Windows PowerShell
.venv\Scripts\Activate.ps1

pip install -r requirements.txt
python deepsec.py https://example.com
```

Python 3.12 ou supérieur est requis. L’outil fonctionne sous Linux et Windows.

## Utilisation

```bash
python deepsec.py https://example.com
python deepsec.py https://example.com --format json --output report.json
python deepsec.py https://example.com --format html --output report.html
python deepsec.py https://example.com --rate-limit 2 --timeout 15 --max-workers 4
python deepsec.py --help
python deepsec.py --version
```

Les plafonds sont volontairement bornés : 0,5–10 requêtes/seconde, 1–10 workers et 1–60 secondes de timeout. Le score sur 100 est un indicateur de triage, jamais une garantie de sécurité.

## Architecture

`deepsec.py` est le point d’entrée. `deepsec/cli.py` orchestre l’exécution, `scanner.py` coordonne les modules asynchrones, `utils/http.py` applique le rate limiting et les garde-fous, et chaque fichier de `deepsec/modules/` retourne ses propres findings. `models.py` définit le contrat commun : titre, sévérité, catégorie, description, preuve, URL, remédiation et références.

## Limites

DeepSec n’est ni un test d’intrusion ni un scanner exhaustif. Il ne fait pas de brute force, d’injection, de fuzzing agressif, d’exploitation, de contournement d’authentification, de SSRF/RCE, d’upload, de suppression, de déni de service ou de scan massif. Les résultats dépendent de la réponse reçue et doivent être validés par l’équipe responsable.

## Contribution et sécurité

Consultez [CONTRIBUTING.md](CONTRIBUTING.md) pour proposer une amélioration et [SECURITY.md](SECURITY.md) pour signaler un problème de sécurité. Toute nouvelle règle doit rester passive, limitée, documentée et testée sans cible Internet réelle.

## Licence

MIT — voir [LICENSE](LICENSE).

