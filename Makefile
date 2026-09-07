PY ?= python3

.PHONY: all update convert clean recommended check

all: update convert

update:                       ## Telecharge / met a jour toutes les listes
	$(PY) fetch_filters.py

recommended:                  ## Uniquement les listes "recommended" d'AdGuard
	$(PY) fetch_filters.py --recommended

convert:                      ## Convertit filters/ -> webkit-rules/
	$(PY) convert_webkit.py

check:                        ## Verifie que tous les JSON produits sont bien formes
	@$(PY) -c "import json,glob,sys; \
	fs=sorted(glob.glob('webkit-rules/*.json')); \
	[json.load(open(f)) for f in fs]; \
	print('%d fichiers JSON valides' % len(fs))"

verify:                       ## macOS uniquement: compile chaque fichier avec le WebKit systeme
	@command -v swift >/dev/null || { echo "swift introuvable (macOS + Command Line Tools requis)"; exit 1; }
	@WK_QUIET=1 swift tools/wk_probe.swift >/dev/null 2>&1 || true
	swift tools/wk_compile.swift webkit-rules/Webkit-*.json

probe:                        ## macOS uniquement: sonde les contraintes reelles de WebKit
	swift tools/wk_probe.swift

catalog:                      ## Affiche le catalogue sans rien telecharger
	$(PY) fetch_filters.py --list

clean:
	rm -rf webkit-rules/*.json reports/*.json reports/*.md
