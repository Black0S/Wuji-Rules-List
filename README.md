# Wuji Rules List

Pipeline en deux étapes : récupérer les listes de filtres adblock connues, puis
les convertir en **Content Blocker JSON natif WebKit** (Safari, iOS / macOS).

```
sources.json ──> fetch_filters.py ──> filters/ ──> convert_webkit.py ──> webkit-rules/
                                                                     └─> reports/
```

| | |
|---|---|
| Listes suivies | **161** |
| Fichiers WebKit générés | **170** |
| Règles WebKit | **2 951 211** |
| Entrées sources analysées | **3 268 178** |
| Entrées non convertibles | **108 408** (détail dans `reports/CONVERSION.md`) |

> Les règles converties sont publiées sur la branche **`dist`**, réécrite à
> chaque exécution — `main` ne contient que les scripts et les rapports.

---

## Démarrage

```bash
make
```

ou :

```bash
python3 fetch_filters.py      # étape 1 : télécharge / met à jour filters/
python3 convert_webkit.py     # étape 2 : écrit webkit-rules/Webkit-<Nom>.json
```

Aucune dépendance : Python 3.7+, bibliothèque standard uniquement.

---

## Étape 1 — `fetch_filters.py`

Découvre automatiquement le catalogue via trois registres, déclarés dans
`sources.json` :

| Registre | Type | Contenu | Défaut |
|---|---|---|---|
| `filters.adtidy.org/extension/chromium/filters.json` | `adguard-registry` | 88 listes : filtres AdGuard + EasyList, EasyPrivacy, Fanboy, uBO, Peter Lowe, Dandelion Sprout, listes par langue et sécurité | activé |
| `adguardteam.github.io/HostlistsRegistry` | `adguard-hostlists` | 64 blocklists DNS : OISD, HaGeZi, 1Hosts, Steven Black, anti-AD, AdRules, Phishing Army… | activé |
| `api.filterlists.com/lists` | `filterlists` | annuaire indépendant, ~2 300 listes (longue traîne, qualité inégale) | désactivé |

Les listes DNS sont de purs blocklists de domaines : elles se convertissent à
~100 % en règles WebKit. Les doublons entre registres sont éliminés par URL.
`extra` dans `sources.json` couvre les listes uBlock Origin absentes des
registres (`unbreak`, `annoyances`, `annoyances-cookies`, les sous-listes
EasyList granulaires…).

Mises à jour **incrémentales** : `filters/index.json` conserve `ETag`,
`Last-Modified`, `sha256` et l'horodatage. Une liste inchangée renvoie un
HTTP 304 et n'est pas retéléchargée ; une liste encore dans sa fenêtre
`! Expires:` n'est même pas interrogée.

```bash
python3 fetch_filters.py --list                  # afficher le catalogue (161 listes)
python3 fetch_filters.py --recommended           # seulement les listes "recommended"
python3 fetch_filters.py --group Privacy Security
python3 fetch_filters.py --tag lang:fr
python3 fetch_filters.py --only easylist ublock  # par motif sur id/nom
python3 fetch_filters.py --force                 # ignorer cache et fraîcheur
```

Sortie : `filters/<Nom-De-La-Liste>.txt` + `filters/index.json` (nom, version,
homepage, licence, groupe, tags, sha256, nombre de règles).

---

## Étape 2 — `convert_webkit.py`

Écrit `webkit-rules/Webkit-<Nom-De-La-Liste>.json` — le nom de la liste
d'origine, préfixé de `Webkit-`.

**Règle d'or : on n'écrit que ce que WebKit sait réellement compiler.** Toute
règle dont la sémantique ne peut pas être rendue fidèlement est écartée et
comptabilisée avec son motif, plutôt que traduite approximativement. Un
validateur final rejette toute règle qui violerait le schéma WebKit — aucun
JSON produit ne peut faire échouer la compilation Safari.

```bash
python3 convert_webkit.py
python3 convert_webkit.py --only AdGuard-Base --pretty
python3 convert_webkit.py --legacy               # profil WebKit ancien
python3 convert_webkit.py --allow-has            # autoriser :has() (Safari 16.4+)
```

### Ce qui est converti

| Syntaxe adblock | Sortie WebKit |
|---|---|
| `\|\|domaine^`, `\|url\|`, `/motif/`, jokers `*` | `trigger.url-filter` |
| `$script,image,font,media,stylesheet,document,popup…` | `resource-type` |
| `$xmlhttprequest`, `$websocket`, `$ping`, `$other` | `fetch` / `websocket` / `ping` / `other` (ou `raw` en `--legacy`) |
| `$subdocument` | `resource-type: document` + `load-context: child-frame` |
| `$~type` (négation) | complément énuméré des types |
| `$third-party` / `$first-party` | `load-type` |
| `$domain=a.com\|b.com` | `if-domain` (`*a.com`) |
| `$domain=~a.com` | `unless-domain` |
| `$match-case` | `url-filter-is-case-sensitive` |
| `$cookie` (sans valeur) | `action: block-cookies` |
| `@@` exception | `action: ignore-previous-rules` |
| `@@$document` / `$elemhide` | `ignore-previous-rules` + `if-top-url` (exception de page entière) |
| `domaine##sélecteur` | `css-display-none` + `if-domain` |
| `domaine#@#sélecteur` | retiré des `if-domain` / ajouté aux `unless-domain` de la règle visée |
| format `hosts` (`0.0.0.0 x.com`) | détecté automatiquement, converti en blocage de domaine |

Alias reconnus : `$xhr`, `$css`, `$frame`, `$doc`, `$from`, `$3p`, `$1p`,
`$popunder`, `$beacon`, `$object-subrequest`.

### Ce qui est écarté (et pourquoi)

Scriptlets (`#%#`, `##+js()`), injection de style (`#$#`), CSS étendu
(`#?#`, `:has-text()`, `:xpath()`, `:upward()`, `:matches-css`…), filtrage HTML
(`$$`), `$csp`, `$redirect`, `$removeparam`, `$removeheader`, `$replace`,
`$permissions`, `$stealth`, `$denyallow`, `$badfilter`, `$app`, `$path`,
`$urlskip`, regex hors du sous-ensemble WebKit (`{n,m}`, `(?=)`, `\d`, `\w`,
alternation `|`, rétro-références), jokers de TLD (`exemple.*`), et `$domain`
mélangeant inclusions et exclusions (interdit par WebKit).

Ces exclusions sont **structurelles** : WebKit n'expose ni exécution de script,
ni réécriture de requête, ni moteur CSS étendu. Le détail chiffré par liste est
dans `reports/<Liste>.report.json`, la synthèse dans `reports/CONVERSION.md`.

### Points de conversion non évidents

**Blocage de la navigation principale.** En adblock, `||pub.com^` ne bloque pas
la navigation vers la page elle-même ; sous WebKit, un trigger sans
`resource-type` couvre aussi `document`. Traduire naïvement rend des sites
entièrement inaccessibles. Le convertisseur insère donc une règle
`ignore-previous-rules` ciblant `resource-type: document` + `load-context:
top-frame`, placée **après** les blocages génériques et **avant** les blocages
qui visent explicitement le document (`$document`, listes sécurité). Réglable
via `--document-policy {guard,enumerate,allow}` ; `enumerate` énumère les types
sur chaque règle (compatible WebKit ancien, JSON plus volumineux).

**L'ordre est sémantique.** WebKit applique le tableau dans l'ordre et
`ignore-previous-rules` n'annule que ce qui précède. Le tableau est donc
assemblé ainsi : blocages → garde document → blocages document → `block-cookies`
→ `css-display-none` → exceptions → exceptions de page entière.

**Séparateur `^`.** En fin de motif il est traduit par une classe
**obligatoire** `[/:&?=,;]` (l'URL canonique testée par WebKit contient toujours
au moins `/`), ce qui évite le faux positif classique où `||exemple.com^`
matcherait `exemple.com.pirate.net`. En milieu de motif il reste optionnel.

**Ancre de domaine.** `||` devient `^[htpsw]+://([a-z0-9-]+\.)*`, qui couvre un
nombre quelconque de sous-domaines sans franchir la limite d'autorité.

**Regroupement CSS.** Les sélecteurs partageant le même trigger sont fusionnés
en une seule règle `css-display-none` (paquets de 250, `--css-group-size`).
Sur AdGuard Base cela ramène ~42 000 sélecteurs à ~14 500 règles.

**Limite des 150 000 règles.** Dépassée, la liste est découpée en
`Webkit-<Nom>-1.json`, `-2.json`… Les exceptions sont **répliquées dans chaque
fichier**, car `ignore-previous-rules` n'agit qu'à l'intérieur d'un même content
blocker compilé.

**IDN.** Les domaines Unicode sont convertis en punycode, le reste est
percent-encodé ; ce qui reste non-ASCII est écarté (WebKit le refuse).

---

## Volume et sélection

Le catalogue complet pèse ~99 Mo de listes brutes et ~334 Mo de JSON WebKit.
Avec le workflow quotidien, l'historique git grossit vite. Trois leviers :

```bash
python3 fetch_filters.py --recommended           # ~40 listes, le socle utile
python3 fetch_filters.py --group "Ad blocking" Privacy Security
```

ou dans `sources.json` : passer le registre `adguard-dns` à `"enabled": false`
(il pèse à lui seul l'essentiel du volume), ou ajouter des identifiants à
`selection.exclude_ids`. Six méga-listes DNS y sont déjà exclues par défaut
(HaGeZi Ultimate / Pro++ / Pro, OISD Big, 1Hosts Xtra, Threat Intelligence
Feeds) : plusieurs centaines de milliers de domaines chacune, largement
redondantes entre elles. Retirer un identifiant de cette liste suffit à la
réintégrer.

## Couverture

Catalogue vérifié contre les deux références :

- **[AdguardTeam/AdguardFilters](https://github.com/AdguardTeam/AdguardFilters)** —
  les 88 filtres du registre sont présents, moins les 2 dépréciés (`#14`
  Annoyances, remplacé par `#18`–`#22` ; `#15` DNS filter, remplacé par le
  registre Hostlists). Les registres `safari`, `ios`, `android`, `mac`,
  `windows`, `firefox` et `ublock` n'exposent aucun filtre supplémentaire :
  les 19 identifiants propres à `mac` sont tous marqués `(Obsolete)`.
- **[uBlock Origin `assets.json`](https://github.com/gorhill/uBlock/blob/master/assets/assets.json)** —
  les 71 listes sont couvertes, soit par l'équivalent AdGuard (comparaison par
  `! Title:` réel, pas par URL : AdGuard remiroite la plupart d'entre elles),
  soit par une entrée `extra` ajoutée pour les 14 absentes.
- **[FilterLists.com](https://filterlists.com/)** — annuaire indépendant de
  ~2 300 listes, disponible en registre optionnel pour la longue traîne.

---

## Arborescence

```
fetch_filters.py        étape 1
convert_webkit.py       étape 2
sources.json            registres + sources supplémentaires + sélection
Makefile                make / make update / make convert / make check
filters/                listes brutes + index.json (état, ETag, sha256)
webkit-rules/           Webkit-<Nom>.json + index.json (catalogue de sortie)
reports/                rapport par liste + CONVERSION.md
.github/workflows/      mise à jour quotidienne automatique
```

`filters/*.txt` et `webkit-rules/*.json` sont ignorés par git sur `main` :
le premier est un cache régénérable en ~20 s, le second est publié sur `dist`.

---

## Automatisation et branche `dist`

[`.github/workflows/update.yml`](.github/workflows/update.yml) rejoue le
pipeline chaque jour à 04:17 UTC (et à chaque modification des scripts ou de
`sources.json`). Il pousse ensuite :

- sur **`main`** : `filters/index.json` et `reports/` — quelques centaines de Ko ;
- sur **`dist`** : les fichiers `Webkit-*.json`, via une branche orpheline
  **force-pushée** à chaque exécution. Un seul commit, pas d'historique : le
  dépôt garde une taille constante malgré les ~334 Mo régénérés quotidiennement.

Les fichiers sont donc consommables directement, avec des URL stables :

```
https://raw.githubusercontent.com/Black0S/Wuji-Rules-List/dist/index.json
https://raw.githubusercontent.com/Black0S/Wuji-Rules-List/dist/Webkit-AdGuard-Base-filter.json
```

Deux prérequis côté GitHub :

1. *Settings → Actions → General → Workflow permissions* → **Read and write
   permissions**. Le jeton par défaut des dépôts récents est en lecture seule et
   le `permissions:` du workflow ne peut pas dépasser ce plafond : sans ce
   réglage, le `git push` échoue.
2. GitHub désactive un workflow planifié après 60 jours sans activité sur le
   dépôt. Si le mail « workflow disabled » arrive, un clic le réactive.

`webkit-rules/*.json` est ignoré par git sur `main` (voir `.gitignore`) :
retirer la ligne pour les versionner localement aussi.

---

## Utiliser un fichier dans Safari

Les fichiers de `webkit-rules/` sont des tableaux JSON de règles, sans
enveloppe : directement consommables par `SFContentBlockerManager`
(app iOS/macOS) ou par la clé `content_blockers` d'une Safari Web Extension.

Safari n'active qu'un nombre limité de content blockers simultanés — choisir
les listes plutôt que toutes les activer.

---

## Licences

Chaque liste reste sous la licence de ses auteurs (champ `license` dans
`filters/index.json`). Ce dépôt ne distribue que des conversions.
