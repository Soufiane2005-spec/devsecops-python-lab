# DevSecOps Python Lab

Petite application Flask destinée à un laboratoire local et autorisé.
Elle contient :

- une page de connexion ;
- un mode volontairement vulnérable à l'injection SQL ;
- un mode sécurisé avec requête paramétrée et mot de passe haché ;
- une liste et un formulaire d'ajout de produits ;
- une page d'administration protégée par le rôle `ADMIN` ;
- des tests automatisés ;
- un premier workflow GitHub Actions.

> Ne jamais exposer le mode vulnérable sur Internet ou sur un réseau non isolé.

## Comptes de démonstration

- `admin` / `Admin123!`
- `user` / `User123!`

## Lancement local

```bash
python -m venv .venv
```

Windows PowerShell :

```powershell
.venv\Scripts\Activate.ps1
pip install -r requirements-dev.txt
python init_db.py
$env:VULNERABLE_MODE="true"
python run.py
```

Linux/macOS :

```bash
source .venv/bin/activate
pip install -r requirements-dev.txt
python init_db.py
VULNERABLE_MODE=true python run.py
```

Ouvrir : <http://127.0.0.1:5000>

## Lancement Docker

```bash
docker compose up --build
```

## Tests

```bash
pytest -q
ruff check .
bandit -r app
pip-audit -r requirements.txt
```

## Modes

- `VULNERABLE_MODE=true` : démonstration locale de l'injection SQL.
- `VULNERABLE_MODE=false` : authentification corrigée.

## Première version du pipeline

Le workflow `.github/workflows/ci.yml` réalise :

1. récupération du code ;
2. installation de Python ;
3. installation des dépendances ;
4. analyse de qualité avec Ruff ;
5. tests avec pytest ;
6. rapports Bandit et pip-audit ;
7. publication des rapports comme artefacts.

Les scans de sécurité sont d'abord informatifs. Ils deviendront bloquants après la phase de correction.
