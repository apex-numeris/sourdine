# Sourdine : cibles de commodité. Le banc lui-même est stdlib pur (aucun pip).
# Ce Makefile est autonome au dossier sourdine/ ; il ne touche pas au Makefile
# racine du dépôt (plateforme).
.PHONY: help test test-regression test-docker run run-docker regen-sample clean site-check site-deploy site-verify

PY ?= python3

help:
	@echo "Cibles Sourdine :"
	@echo "  make test          - tests sans docker : non-regression sim, determinisme, interface, paires jumelles"
	@echo "  make test-regression - le seul module de non-regression sim, en mode verbeux"
	@echo "  make test-docker   - non-regression LIVE du backend docker (~25 min, opt-in)"
	@echo "  make run           - lance une campagne sim (defaut)"
	@echo "  make run-docker    - lance une campagne sur vraie cible docker ephemere"
	@echo "  make regen-sample  - RE-GELE samples/example-0.1.0.json (geste delibere)"
	@echo "  make site-check    - la page site/index.html est-elle au niveau de VERSION et des echantillons geles ?"
	@echo "  make site-deploy   - copie site/ vers le serveur web (SOURDINE_WEB=utilisateur@hote)"
	@echo "  make site-verify   - sourdine.org sert-il la page du depot ? (empreinte SHA-256)"
	@echo "  make clean         - purge reports/ et les caches Python"

test:
	$(PY) -m unittest discover -s tests -t . -p 'test_*.py' -v

test-regression:
	$(PY) -m unittest -v tests.test_sim_regression

# Non-régression LIVE du backend docker : lance une vraie cible éphémère
# (Prometheus + Alertmanager, ~25 min). Opt-in via la variable d'env.
test-docker:
	SOURDINE_DOCKER_TEST=1 $(PY) -m unittest -v tests.test_docker_regression

run:
	$(PY) run_campaign.py

run-docker:
	$(PY) run_campaign.py --backend docker

# Re-gele l'echantillon citable a partir d'un run sim frais. A n'utiliser que
# lorsqu'un changement de comportement est VOULU : relire `git diff` avant commit.
regen-sample:
	$(PY) run_campaign.py --backend sim --out samples/example-0.1.0.json --quiet
	@echo "-> samples/example-0.1.0.json re-gele. Relire 'git diff' avant de committer."

# Page servie à la racine de sourdine.org. `site-check` tourne aussi dans `make test`.
site-check:
	$(PY) -m unittest -v tests.test_site_page

# Publie la page versionnée. SOURDINE_WEB = cible ssh du serveur web, jamais écrite dans le dépôt.
site-deploy: site-check
	@test -n "$(SOURDINE_WEB)" || { echo "SOURDINE_WEB manquant : make site-deploy SOURDINE_WEB=utilisateur@hote"; exit 2; }
	scp site/index.html site/robots.txt $(SOURDINE_WEB):/var/www/sourdine/

# Compare l'empreinte de la page du dépôt à celle de la page servie.
site-verify:
	@depot=$$(sha256sum site/index.html | cut -d' ' -f1); \
	 ligne=$$(curl -fsS https://sourdine.org/ | sha256sum | cut -d' ' -f1); \
	 if [ "$$depot" = "$$ligne" ]; then echo "sourdine.org sert la page du depot ($$depot)"; \
	 else echo "ECART : depot $$depot, en ligne $$ligne"; exit 1; fi

clean:
	rm -rf reports/*.json __pycache__ engine/__pycache__ tests/__pycache__
