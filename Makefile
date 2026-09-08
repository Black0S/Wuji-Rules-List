PY ?= python3

.PHONY: all update convert clean recommended check test verify probe redundancy

all: update convert

update:                       ## Telecharge / met a jour toutes les listes
	$(PY) fetch_filters.py

recommended:                  ## Uniquement les listes "recommended" d'AdGuard
	$(PY) fetch_filters.py --recommended

convert:                      ## Convertit filters/ -> webkit-rules/
	$(PY) convert_webkit.py

test:                         ## Non-regression du convertisseur (portable)
	$(PY) tests.py

check: test                   ## Tests + controle structurel des fichiers produits
	@$(PY) -c "import json,glob; \
	fs=sorted(glob.glob('webkit-rules/*.json')+glob.glob('webkit-rules/extended/*.json')); \
	[json.load(open(f)) for f in fs]; \
	print('%d fichiers JSON bien formes' % len(fs))"
	$(PY) tools/validate.py

verify:                       ## macOS uniquement: compile chaque fichier avec le WebKit systeme
	@command -v swift >/dev/null || { echo "swift introuvable (macOS + Command Line Tools requis)"; exit 1; }
	@WK_QUIET=1 swift tools/wk_probe.swift >/dev/null 2>&1 || true
	swift tools/wk_compile.swift webkit-rules/Webkit-*.json

probe:                        ## macOS uniquement: sonde les contraintes reelles de WebKit
	swift tools/wk_probe.swift

redundancy:                   ## Annote sources.json avec le recouvrement entre listes
	$(PY) tools/redundancy.py

redundancy-report:            ## Affiche le recouvrement sans rien ecrire
	$(PY) tools/redundancy.py --dry-run

catalog:                      ## Affiche le catalogue sans rien telecharger
	$(PY) fetch_filters.py --list

clean:
	rm -rf webkit-rules/*.json webkit-rules/extended reports/*.json reports/*.md
