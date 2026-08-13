# Contribuer

Les contributions sont les bienvenues si elles renforcent la qualité et la sécurité du projet.

- utilisez Python 3.12+, les type hints et des modules courts ;
- conservez les requêtes strictement passives et HTTP(S) ;
- ajoutez des tests mockés pour chaque nouveau comportement ;
- lancez `ruff check .`, `python -m compileall -q deepsec deepsec.py` et `pytest -q` avant une pull request ;
- documentez la preuve, la sévérité et la remédiation de toute nouvelle règle.

N’ajoutez pas de cible Internet réelle dans les tests ou les exemples automatisés.

