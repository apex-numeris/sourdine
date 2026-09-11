# Sourdine — cibles de commodité. Le banc lui-même est stdlib pur (aucun pip).
# Ce Makefile est autonome au dossier sourdine/ ; il ne touche pas au Makefile
# racine du dépôt (plateforme).
.PHONY: help test test-regression run run-docker regen-sample clean

PY ?= python3

help:
	@echo "Cibles Sourdine :"
	@echo "  make test          - non-regression du run sim + determinisme (stdlib unittest)"
	@echo "  make test-regression - le seul module de non-regression, en mode verbeux"
	@echo "  make run           - lance une campagne sim (defaut)"
	@echo "  make run-docker    - lance une campagne sur vraie cible docker ephemere"
	@echo "  make regen-sample  - RE-GELE samples/example-0.1.0.json (geste delibere)"
	@echo "  make clean         - purge reports/ et les caches Python"

test:
	$(PY) -m unittest discover -s tests -t . -p 'test_*.py' -v

test-regression:
	$(PY) -m unittest -v tests.test_sim_regression

run:
	$(PY) run_campaign.py

run-docker:
	$(PY) run_campaign.py --backend docker

# Re-gele l'echantillon citable a partir d'un run sim frais. A n'utiliser que
# lorsqu'un changement de comportement est VOULU : relire `git diff` avant commit.
regen-sample:
	$(PY) run_campaign.py --backend sim --out samples/example-0.1.0.json --quiet
	@echo "-> samples/example-0.1.0.json re-gele. Relire 'git diff' avant de committer."

clean:
	rm -rf reports/*.json __pycache__ engine/__pycache__ tests/__pycache__
