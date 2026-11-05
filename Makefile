# Environnement de developpement de copilot-pii-gateway.
# Usage : make help
#
# Les cibles n'ecrivent que dans le depot et le venv. `make run` et `make px`
# lancent des processus locaux au premier plan. Aucune CA n'est installee dans un magasin
# systeme : cette etape reste manuelle et soumise a l'accord securite.

SHELL := /bin/sh
.DEFAULT_GOAL := help

PYTHON        ?= python3
PYTHON_MIN    ?= 3.12
VENV          ?= .venv
POLICY        ?= policy.json
PX_CONFIG     ?= px.ini
PRESIDIO_MODEL ?= fr_core_news_lg
CANARY_PROXY  ?= http://127.0.0.1:8080
DOCKER        ?= docker
LAB_FILES     ?= -f lab/compose.yaml
LAB_BUILD     ?= --build
LAB           := $(DOCKER) compose $(LAB_FILES)

ifeq ($(OS),Windows_NT)
  VENV_BIN := $(VENV)/Scripts
  EXE      := .exe
else
  VENV_BIN := $(VENV)/bin
  EXE      :=
endif

PY      := $(VENV_BIN)/python$(EXE)
PIP     := $(PY) -m pip
MITMDUMP := $(VENV_BIN)/mitmdump$(EXE)
STAMP_BASE     := $(VENV)/.installed-base
STAMP_PRESIDIO := $(VENV)/.installed-presidio
STAMP_PX       := $(VENV)/.installed-px
SOURCES := pii_config.py pii_core.py pii_detector.py pii_worker.py copilot_pii.py gateway.py \
           check_proxy.py check_config.py fake_worker.py \
           test_core.py test_addon.py test_regressions.py test_worker.py test_gateway.py \
           lab/fake_copilot.py lab/pki.py lab/test_lab.py

.PHONY: help setup setup-presidio check-python venv install install-presidio \
        install-px presidio-model test compile policy-check config-check check ca ca-path \
        px-config run px canary doctor clean distclean \
        lab lab-up lab-test lab-logs lab-shell lab-collect lab-down

help: ## Afficher cette aide
	@echo "Cibles disponibles :"
	@awk 'BEGIN {FS = ":.*## "} /^[a-zA-Z_-]+:.*## / {printf "  %-16s %s\n", $$1, $$2}' $(MAKEFILE_LIST)
	@echo ""
	@echo "Variables : PYTHON=$(PYTHON) VENV=$(VENV) POLICY=$(POLICY) PRESIDIO_MODEL=$(PRESIDIO_MODEL)"

# --- Preparation -----------------------------------------------------------

setup: install ca check ## Tout preparer : venv, mitmproxy, CA locale et verifications
	@echo "Environnement pret. Etapes manuelles restantes : make doctor"

setup-presidio: setup install-presidio presidio-model ## setup + Presidio et modele spaCy

check-python: ## Verifier la version de Python (3.12 minimum par defaut)
	@$(PYTHON) -c "import sys; m=tuple(map(int,'$(PYTHON_MIN)'.split('.'))); \
	sys.exit(0) if sys.version_info[:2] >= m else sys.exit('Python >= $(PYTHON_MIN) requis, trouve ' + sys.version.split()[0])"
	@$(PYTHON) -c "import venv" || { echo "Module venv absent (Debian/Ubuntu : paquet python3-venv)"; exit 1; }

venv: $(PY) ## Creer l'environnement virtuel

$(PY):
	@$(MAKE) --no-print-directory check-python
	$(PYTHON) -m venv $(VENV)
	$(PIP) install --quiet --upgrade pip

install: $(STAMP_BASE) ## Installer les dependances (mitmproxy)

$(STAMP_BASE): requirements.txt | $(PY)
	$(PIP) install -r requirements.txt
	@touch $@

install-presidio: $(STAMP_PRESIDIO) ## Installer Presidio et spaCy (facultatif)

$(STAMP_PRESIDIO): requirements-presidio.txt | $(STAMP_BASE)
	$(PIP) install -r requirements-presidio.txt
	@touch $@

presidio-model: $(STAMP_PRESIDIO) ## Telecharger le modele spaCy (PRESIDIO_MODEL=...)
	@if $(PY) -c "import spacy, sys; sys.exit(0 if spacy.util.is_package('$(PRESIDIO_MODEL)') else 1)"; then \
		echo "Modele $(PRESIDIO_MODEL) deja installe"; \
	else \
		echo "Telechargement de $(PRESIDIO_MODEL) (en reseau ferme, utiliser le miroir approuve)"; \
		$(PY) -m spacy download $(PRESIDIO_MODEL); \
	fi
	@echo "Activer ensuite presidio_language, presidio_model et presidio_score dans $(POLICY)"

# --- Verifications ---------------------------------------------------------

compile: $(PY) ## Compiler les sources Python
	$(PY) -m py_compile $(SOURCES)

test: $(STAMP_BASE) ## Lancer les tests unitaires (mitmproxy installe pour les tests du lanceur)
	$(PY) -m unittest -v

policy-check: $(PY) ## Valider la politique (parsing strict + validate_config)
	@$(PY) -c "import sys; from pathlib import Path; from pii_core import loads; \
	from pii_config import validate_config, ConfigurationError; \
	cfg = validate_config(loads(Path('$(POLICY)').read_bytes())); \
	print('Politique valide :', '$(POLICY)', '- mode', cfg.get('mode', 'block'))"

config-check: $(STAMP_BASE) ## Valider config.yaml avec le gestionnaire d'options mitmproxy
	$(PY) check_config.py config.yaml
	@if grep -q 'proxy.entreprise.example' config.yaml; then \
		echo "Attention : config.yaml pointe encore vers le proxy d'exemple"; fi

check: compile test policy-check config-check ## compile + test + policy-check + config-check

# --- Certificat et proxy ---------------------------------------------------

ca: $(STAMP_BASE) ## Generer la CA mitmproxy locale dans le depot (ignoree par Git)
	@$(PY) -c "from mitmproxy.certs import CertStore; CertStore.from_store('.', 'mitmproxy', 2048)"
	@echo "CA publique : $(CURDIR)/mitmproxy-ca-cert.pem (ne jamais diffuser mitmproxy-ca.pem)"

ca-path: ## Afficher le certificat public a installer manuellement
	@test -f mitmproxy-ca-cert.pem || { echo "Lancer d'abord : make ca"; exit 1; }
	@echo "$(CURDIR)/mitmproxy-ca-cert.pem"

px-config: ## Creer px.ini a partir de px.ini.example (sans ecraser)
	@if [ -f $(PX_CONFIG) ]; then echo "$(PX_CONFIG) existe deja"; \
	else cp px.ini.example $(PX_CONFIG); echo "$(PX_CONFIG) cree : adapter server"; fi

run: $(STAMP_BASE) policy-check ## Lancer la passerelle (gateway.py, addon integre, sans rechargement)
	COPILOT_PII_CONFIG=$(POLICY) $(PY) gateway.py --set confdir=.

install-px: $(STAMP_PX) ## Installer Px pour NTLM/Kerberos (facultatif)

$(STAMP_PX): requirements-px.txt | $(PY)
	$(PIP) install -r requirements-px.txt
	@touch $@

px: $(STAMP_PX) ## Lancer Px avec px.ini (proxy local 127.0.0.1:3128)
	@test -f $(PX_CONFIG) || { echo "Lancer d'abord : make px-config"; exit 1; }
	$(VENV_BIN)/px$(EXE) --config=$(PX_CONFIG)

canary: $(PY) ## Interroger le canari du proxy demarre (make run dans un autre terminal)
	$(PY) check_proxy.py

doctor: ## Etat de l'environnement et etapes manuelles
	@printf "Python systeme   : "; $(PYTHON) --version 2>&1 || true
	@printf "Venv             : "; if [ -x $(PY) ]; then $(PY) --version; else echo "absent (make venv)"; fi
	@printf "mitmproxy        : "; if [ -x $(MITMDUMP) ]; then $(MITMDUMP) --version 2>/dev/null | head -1; else echo "absent (make install)"; fi
	@printf "Presidio         : "; if [ -f $(STAMP_PRESIDIO) ]; then echo "installe"; else echo "non installe (facultatif)"; fi
	@printf "CA locale        : "; if [ -f mitmproxy-ca-cert.pem ]; then echo "presente"; else echo "absente (make ca)"; fi
	@printf "Px               : "; if [ -f $(STAMP_PX) ]; then echo "installe"; else echo "non installe (facultatif)"; fi
	@printf "px.ini           : "; if [ -f $(PX_CONFIG) ]; then echo "present"; else echo "absent (make px-config si NTLM/Kerberos)"; fi
	@printf "Proxy amont      : "; grep -E '^\s*-\s*upstream:' config.yaml | sed 's/^ *- *//'
	@echo ""
	@echo "Etapes manuelles :"
	@echo "  1. Adapter le proxy amont dans config.yaml (ou upstream:http://127.0.0.1:3128 avec Px)."
	@echo "  2. Installer mitmproxy-ca-cert.pem dans le magasin reconnu par Copilot, avec accord securite."
	@echo "  3. VS Code : {\"http.proxy\": \"$(CANARY_PROXY)\", \"http.proxyStrictSSL\": true}"
	@echo "  4. make run, puis make canary avant toute utilisation."

# --- Lab d'integration (Docker) ---------------------------------------------

lab-up: ## Demarrer le lab (etat propre) : PKI, faux Copilot, Squid, passerelles
	$(LAB) up -d $(LAB_BUILD) --force-recreate --wait

lab-test: lab-up ## Lancer les tests d'integration et la verification de demarrage (F4)
	$(LAB) run --rm tests
	$(LAB) --profile faults run --rm startup-check

lab-logs: ## Suivre les journaux du lab
	$(LAB) logs -f

lab-shell: ## Shell dans la passerelle redact
	$(LAB) exec gateway-redact sh

lab-collect: ## Copier journaux et enregistrements amont dans lab/out (diagnostic, CI)
	@mkdir -p lab/out
	-$(LAB) logs --no-color > lab/out/logs.txt 2>&1
	-$(LAB) cp fake-copilot:/recordings lab/out/
	-$(LAB) exec -T corp-proxy cat /var/log/squid/access.log > lab/out/squid-access.log

lab-down: ## Arreter le lab et supprimer ses volumes
	$(LAB) --profile test --profile faults down -v --remove-orphans

lab: ## Cycle complet : demarrage, tests, arret garanti
	@status=0; $(MAKE) --no-print-directory lab-test || status=$$?; \
	if [ $$status -ne 0 ]; then $(MAKE) --no-print-directory lab-collect; fi; \
	$(MAKE) --no-print-directory lab-down; exit $$status

# --- Nettoyage -------------------------------------------------------------

clean: ## Supprimer les caches Python
	find . -name '__pycache__' -type d -prune -not -path './$(VENV)/*' -exec rm -rf {} +
	rm -rf .pytest_cache .coverage htmlcov

distclean: clean ## clean + supprimer le venv (la CA locale est conservee)
	rm -rf $(VENV)
