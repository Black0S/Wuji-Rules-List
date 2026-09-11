# Wuji Rules List

Pipeline en deux étapes : récupérer les listes de filtres adblock connues, puis
les convertir en **Content Blocker JSON natif WebKit** (Safari, iOS / macOS).

```
sources.json ──> fetch_filters.py ──> filters/ ──> convert_webkit.py ──> webkit-rules/
                                                                     └─> reports/
```

| | |
|---|---|
| Listes au catalogue | **71** dans 11 groupes, toutes publiées |
| Fichiers WebKit générés | **79** |
| Règles WebKit | **1 855 568** distinctes (1 860 197 émises) |
| Entrées sources analysées | **2 104 242** |
| Entrées non convertibles | **68 482** (détail dans `reports/CONVERSION.md`) |
| Règles consignées pour un moteur à injection | **58 675** (`webkit-rules/extended/`) |

> Publié sur la branche **`dist`**, réécrite à chaque exécution, après
> compilation effective par le WebKit du système — `main` ne contient que les
> scripts et les rapports.

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

Le catalogue est **explicite** : une entrée par liste dans `sources.json`, avec
l'URL complète du dépôt de son propre mainteneur. Aucune découverte
automatique, aucun registre interrogé, aucun miroir, aucun CDN tiers — rien qui
puisse changer sous les pieds sans apparaître dans un diff.

| Groupe | Mainteneur | Listes |
|---|---|---:|
| `ublock` | uBlock Origin | 8 |
| `adguard` | AdGuard | 13 |
| `adguard-dns` | AdGuard DNS | 2 |
| `adguard-lang` | AdGuard (langues) | 9 |
| `easylist` | EasyList | 4 |
| `easylist-lang` | EasyList (regions) | 17 |
| `fanboy` | Fanboy | 4 |
| `dandelion` | Dandelion Sprout | 2 |
| `hagezi` | HaGeZi | 10 |
| `phishing-army` | Phishing Army | 1 |
| `stevo-ai` | Stevo's AI Blocklist | 2 |

**Ajouter une liste** — choisir le groupe, écrire trois champs :

```json
{ "id": "mon-id", "name": "Nom affiché", "url": "https://…/liste.txt" }
```

`"enabled": false` la désactive sans la supprimer ; `"format": "hosts"` pour un
fichier hosts (la détection reste de toute façon automatique) ; `"note"` pour
un commentaire. Les identifiants sont lisibles et servent de clé stable dans
les index et les rapports.

Le fichier étant fait pour être édité à la main, une erreur de syntaxe est
signalée avec sa ligne, son contexte et un indice — une virgule en trop après
la dernière entrée d'un tableau est le cas le plus fréquent.

**Listes-manifestes.** Les directives `!#include` d'uBlock Origin sont résolues
récursivement : sans cela, `uBlock filters – Annoyances` ou `RU AdList for uBO`
ne sont que des sommaires et arrivent vides. Les blocs conditionnels `!#if`
sont évalués pour la cible réelle — un content blocker Safari, donc
`env_safari`, `adguard_ext_safari` et `adguard` vrais, tout le reste faux —
pour ne pas importer les branches destinées à d'autres moteurs. Une liste à
`!#include` ignore le cache `ETag` : son sommaire peut ne pas bouger alors que
ses parties changent.

**Doublons et orphelins.** Deux entrées qui livrent le même contenu sont
détectées par un hachage des seules règles, en-têtes exclus. Un `.txt` dont la
liste a été retirée du catalogue est supprimé automatiquement, pour ne pas être
converti en liste fantôme.

Mises à jour **incrémentales** : `filters/index.json` conserve `ETag`,
`Last-Modified`, `sha256` et l'horodatage. Une liste inchangée renvoie un
HTTP 304 et n'est pas retéléchargée ; une liste encore dans sa fenêtre
`! Expires:` n'est même pas interrogée.

```bash
python3 fetch_filters.py --list                  # afficher le catalogue
python3 fetch_filters.py --group ublock adguard  # un ou plusieurs groupes
python3 fetch_filters.py --only easylist hagezi  # par motif sur id/nom
python3 fetch_filters.py --force                 # ignorer cache et fraîcheur
```

Sortie : `filters/<Nom-De-La-Liste>.txt` + `filters/index.json` (nom, version,
homepage, licence, groupe, sha256, nombre de règles).

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
python3 convert_webkit.py --safari-version 15   # cible une version anterieure
python3 convert_webkit.py --legacy               # profil WebKit ancien
python3 convert_webkit.py --no-has               # exclure :has() (Safari < 16.4)
```

`:has()` est accepté par défaut : le compilateur de content blocker de WebKit
le valide nativement (vérifié, voir plus bas). Cela représente ~14 000 règles
qui seraient sinon perdues.

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
| `règle$badfilter` | **rétractation appliquée** : la règle visée est retirée de la sortie |
| `$dnsrewrite=` vers une adresse de blocage | traduit en `block` (réécrire vers le trou noir d'un résolveur *est* un blocage) |
| `[$path=/x]domaine##sélecteur` | `if-top-url` encodant domaine **et** chemin — une seule condition, comme l'exige WebKit |
| `$denyallow=a\|b` | le blocage, suivi d'exceptions combinant chaque domaine **au motif d'origine**, placées juste après lui |
| `exemple.*` (tout TLD), `$domain=/regex/` | `if-frame-url` — Safari 26+ ; sinon repli sur l'expansion de ~115 TLD |
| `$method=get` | `request-method` — Safari 26+ ; une seule méthode, négation non supportée |
| `\d` `\w` `\s` | réécrits en `[0-9]`, `[a-zA-Z0-9_]`, `[ ]` (synonymes exacts) |
| `/(a\|b)/` alternation | éclatée en N règles distinctes (WebKit ne sait pas faire de disjonction) |
| `exemple.*` joker de TLD | étendu vers ~115 extensions réellement rencontrées |
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

## Le catalogue `webkit-rules/index.json`

`schema: 2`. Chaque entrée porte son identité complète — `id`, `source_sha256`,
`version`, `converted_at`, `rules_in`, `rules_unique`, `rules_emitted`,
`skipped`, `group`, `homepage`, `license` — de quoi distinguer deux listes de
même nom et savoir exactement de quel instantané une conversion provient.

**Les chemins sont relatifs à la racine du catalogue**, et valent tels quels
sur la branche `dist` comme en local : `Webkit-<Nom>.json` à la racine,
`extended/Extended-<Nom>.json` pour les annexes.

**Deux comptages, volontairement distincts.** `rules_unique` compte les règles
distinctes ; `rules_emitted` additionne les fichiers et inclut donc les
exceptions répliquées dans chaque tranche d'une liste découpée. L'écart (4 627
aujourd'hui) ne porte que sur les listes en plusieurs morceaux ; c'est correct
pour WebKit, mais les deux chiffres ne sont pas comparables et le catalogue les
expose séparément plutôt que d'en choisir un.

**Listes non publiées.** Une liste dont le rendement est négligeable —
`AdGuard URL Tracking`, 1 règle sur 2 638, tout en `$removeparam` — n'est pas
écrite : la proposer inviterait à un clic sans effet. Elle apparaît dans
`unpublished[]` avec son motif, jamais dans `lists[]`. Seuils réglables via
`--min-rules` et `--min-yield`.

---

## Règles à injection : `extended-rules/`

Ce qui ne peut pas devenir une règle WebKit n'est plus simplement compté puis
jeté. Chaque liste produit un `webkit-rules/extended/Extended-<Nom>.json` qui consigne,
sous forme structurée, les règles qu'un moteur à injection — c'est-à-dire une
Safari Web Extension — saurait appliquer :

```json
{"name":"set-constant","args":["urlAds",""],"domains":["mphimtv.my"],
 "excluded":[],"syntax":"adguard","exception":false}
```

Quatre familles, **69 874 entrées** au total :

| Famille | Nombre | Mécanisme requis |
|---|---:|---|
| `scriptlets` | 29 842 | monde principal pour ~40 % d'entre eux, monde isolé pour le reste |
| `styles` (injection `#$#`) | 24 439 | CSS arbitraire, monde isolé |
| `procedural` (`:has-text()`, `:xpath()`…) | 15 474 | inspection DOM, monde isolé |
| `html` (filtrage `$$`) | 119 | réécriture de la réponse |

Le JavaScript libre (539 occurrences) est compté mais **pas** consigné : ce
n'est pas une primitive nommée, le réutiliser reviendrait à exécuter du code
arbitraire sans audit possible.

Ces fichiers **ne sont pas chargeables par Safari**. Ils ne changent ni
l'architecture ni les performances du content blocker ; ils existent pour que
les données soient prêtes et à jour le jour où une extension les consomme, et
pour rendre les rapports auditables plutôt que purement comptables.
`--no-extended` les désactive.

---

## Vérification par le compilateur de Safari

La validation Python ne fait qu'*approcher* les contraintes de WebKit. Deux
outils Swift interrogent le compilateur réel du système — le même que celui
qu'utilise Safari, via `WKContentRuleListStore` :

```bash
make probe      # sonde: ce que WebKit accepte vraiment (batterie de cas)
make verify     # compile chacun des fichiers produits, echoue si l'un est rejete
```

`make verify` est la barrière de publication en CI : le workflow tourne sur un
runner macOS et ne pousse sur `dist` que si les 167 fichiers compilent.

Contraintes établies par la sonde, et non par la documentation :

| Construction | Verdict | Conséquence |
|---|---|---|
| `:has()`, `:is()`, `:where()`, `:nth-child()`, `::before` | accepté | `:has()` activé par défaut |
| `:has-text()`, `:xpath()` et consorts | règle silencieusement jetée | écartées en amont, pour ne pas perdre sans le dire |
| alternation `(a\|b)` | `Disjunctions are not supported yet` | rejetée |
| `{n,m}` | `Arbitrary atom repetitions are not supported` | rejetée |
| `\d` `\w` `\s` | `Character class is not supported` | rejetée |
| `(?=…)` lookahead | refusé | rejetée |
| `^` hors début, `$` hors fin | refusé | rejetée |
| accolade échappée `\{` | accepté | conservée |
| non-greedy `.*?` | accepté | conservée |
| url-filter non-ASCII | refusé | punycode + percent-encoding |
| **plus d'une** clé parmi `if-domain`, `unless-domain`, `if-top-url`, `unless-top-url` | **échec de compilation du fichier entier** | une seule condition émise |
| condition `[]` vide | échec du fichier entier | jamais émise |
| domaine majuscule ou Unicode | échec du fichier entier | minuscule + punycode |
| `resource-type` / `load-context` inconnu | échec du fichier entier | liste blanche stricte |
| tableau de règles vide | `Empty extension` | fichier non écrit |
| clé de trigger inconnue | ignorée | filtrée quand même |

Les quatre entrées marquées « échec du fichier entier » sont le piège
principal : contrairement à un sélecteur CSS invalide qui est simplement
ignoré, une seule règle fautive rend **tout le fichier** inutilisable dans
Safari. C'est ce qui rend `make verify` nécessaire.

---

## Version de Safari visée

`--safari-version` (défaut **26**) gouverne les capacités récentes du moteur,
toutes établies par `tools/wk_probe.swift` sur le compilateur réel :

| Capacité | Sans elle |
|---|---|
| `if-frame-url` / `unless-frame-url` | `exemple.*` retombe sur l'expansion de ~115 TLD, `$domain=/regex/` est perdu |
| `request-method` | `$method` est écarté |

Sur ce catalogue, viser 26 traduit **3 546** jokers de TLD et **410** `$domain`
en regex exactes, et fait passer de 3 188 à 451 le nombre de règles portant un
tableau de plus de 50 domaines. En contrepartie, la sortie exige Safari 26+ :
`--safari-version 15` couvre plus large au prix de ces règles.

## Redondance : le champ `covered_by`

Deux listes du catalogue peuvent bloquer largement la même chose. Rien ne le
signalait, alors qu'un content blocker Safari ne compile que 150 000 règles :
en activer deux qui se recouvrent gaspille ce budget sans rien ajouter.

`tools/redundancy.py` mesure, sur la sortie réelle, la part des règles de
blocage d'une liste déjà présentes dans une autre, et l'écrit dans son entrée :

```json
{
  "id": "easylist",
  "name": "EasyList",
  "url": "https://easylist.to/easylist/easylist.txt",
  "covered_by": [
    { "id": "adguard-base", "name": "AdGuard Base filter", "pct": 100 }
  ]
}
```

**Huit listes sont couvertes à 100 %** — elles n'apportent rien si celle qui
les contient est activée :

| Liste | Entièrement contenue dans |
|---|---|
| EasyList | AdGuard Base filter |
| EasyList Cookie List | Fanboy's Annoyances |
| Fanboy's Social Blocking List | Fanboy's Annoyances |
| EasyList China / Dutch / Germany | AdGuard Chinese / Dutch / German |
| Liste FR | AdGuard French filter |
| Adblock Warning Removal List | RU AdList for uBO |

Le champ est purement informatif : il n'a aucun effet sur la conversion, il
permet à un consommateur du catalogue d'avertir avant que l'utilisateur active
deux fois la même chose.

```bash
make redundancy          # annote sources.json
make redundancy-report   # affiche sans rien ecrire
```

## Sélection

Activer une partie du catalogue ne demande pas de toucher au fichier :

```bash
python3 fetch_filters.py --group ublock adguard easylist
python3 convert_webkit.py --only AdGuard-Base EasyList
```

Pour retirer durablement une liste, mettre `"enabled": false` sur son entrée :
elle reste documentée dans `sources.json` et se réactive d'un mot.

Une liste dont le rendement WebKit est négligeable n'est pas publiée même si
elle est activée — voir `unpublished[]` dans le catalogue de sortie.

## Provenance

Chaque URL a été vérifiée individuellement : réponse HTTP 200, contenu de
filtre effectif, pas de page HTML. Toutes pointent le domaine du mainteneur.

| Hôte | Listes |
|---|---:|
| `filters.adtidy.org` | 22 — dépôt d'AdGuard pour ses propres filtres |
| `raw.githubusercontent.com` | 17 |
| `easylist-downloads.adblockplus.org` | 14 |
| `ublockorigin.github.io` | 8 |
| `easylist.to` | 4 |
| autres domaines de mainteneurs | 7 |

Ce qui n'y figure pas est délibéré : les listes tierces qu'AdGuard redistribue
sans que leur mainteneur publie d'URL brute stable ont été écartées plutôt que
tirées d'un miroir, et jsDelivr a été remplacé par les dépôts qu'il servait.

## Arborescence

```
fetch_filters.py        étape 1
convert_webkit.py       étape 2
sources.json            catalogue explicite: groupes -> listes -> URL
Makefile                update / convert / check / verify / probe
tools/                  sondes Swift du compilateur WebKit (macOS)
filters/                listes brutes + index.json (état, ETag, sha256)
webkit-rules/           Webkit-<Nom>.json + index.json (catalogue de sortie)
webkit-rules/extended/  Extended-<Nom>.json (regles a injection, hors WebKit)
reports/                rapport par liste + CONVERSION.md (non versionnes)
.github/workflows/      mise à jour quotidienne automatique
```

`main` ne versionne que le code, `sources.json` et la documentation — onze
fichiers. `filters/`, `webkit-rules/` et `reports/` sont ignorés par git et
publiés sur `dist`.

---

## Automatisation et branche `dist`

[`.github/workflows/update.yml`](.github/workflows/update.yml) rejoue le
pipeline chaque jour à 04:17 UTC, et à chaque modification des scripts, de
`sources.json` ou de `tools/`.

**La CI ne commite rien sur `main`.** Tout ce que la machine produit part sur
la branche orpheline **`dist`**, force-pushée à chaque exécution : un seul
commit, pas d'historique, taille constante. C'est ce qui garantit que `main`
reste le dépôt de l'auteur et ne diverge jamais du distant.

`dist` contient :

```
Webkit-<Nom>.json          les regles, a la racine
extended/                  les regles a injection
index.json                 le catalogue de sortie
reports/                   un rapport par liste + CONVERSION.md
filters-index.json         l'etat des sources (ETag, sha256, versions)
sources.json               copie du catalogue, annotee `covered_by`
```

URL stables :

```
https://raw.githubusercontent.com/Black0S/Wuji-Rules-List/dist/index.json
https://raw.githubusercontent.com/Black0S/Wuji-Rules-List/dist/Webkit-AdGuard-Base-filter.json
```

Le job tourne sur **`macos-latest`** : `make verify` compile chaque fichier
avec le WebKit du système avant publication, et rien n'est poussé si un seul
est rejeté. Les runners macOS sont gratuits sur les dépôts publics.

Prérequis côté GitHub : *Settings → Actions → General → Workflow permissions* →
**Read and write permissions**, sans quoi le force-push sur `dist` échoue.

> `covered_by` dans le `sources.json` de `main` n'est pas rafraîchi par la CI,
> puisqu'elle n'y écrit plus. Lancer `make redundancy` localement pour le
> mettre à jour ; la copie publiée sur `dist` est, elle, toujours à jour.

## Principe : un fichier par liste

Le découpage est **un content blocker par liste du catalogue**, et non des
bundles par catégorie comme le font les produits finis. C'est un choix assumé :
la granularité laisse à l'utilisateur un contrôle réel sur ce qu'il active,
liste par liste, au lieu de cocher « Confidentialité » sans savoir ce qu'il y a
dedans.

Ce choix a une contrepartie qu'il faut connaître : **une exception ne traverse
pas les fichiers**. Un `@@` présent dans un fichier ne peut annuler qu'un
blocage du même fichier. Les listes composées majoritairement d'exceptions sont
donc inertes si on les charge seules :

| Liste | Exceptions | Effet seule |
|---|---:|---|
| HaGeZi's Allowlist Referral | 100 % | aucun |
| uBlock Origin - Unbreak | 85 % | aucun |
| Filter unblocking search ads | 79 % | aucun |

Ce sont des listes compagnes : elles existent pour corriger le sur-blocage
d'une liste parente (`uBlock Origin - Filters` pour `Unbreak`). C'est aussi ce
que la directive `!#safari_cb_affinity` sert à résoudre chez AdGuard, et
pourquoi nous la traitons en simple commentaire — elle n'a pas de sens hors
d'un modèle par catégorie.

---

## Utiliser un fichier dans Safari

Les fichiers de `webkit-rules/` sont des tableaux JSON de règles, sans
enveloppe : directement consommables par `SFContentBlockerManager`
(app iOS/macOS) ou par la clé `content_blockers` d'une Safari Web Extension.

La limite documentée par Apple porte sur les **règles**, pas sur le nombre de
blockers : 150 000 par content blocker. Rien n'interdit d'en enregistrer
plusieurs — AdGuard en utilise six, ce qui est un choix de conception, non un
plafond d'Apple. En revanche chaque blocker actif coûte sa compilation et sa
mémoire, et surtout **une exception ne traverse pas les blockers** : un `@@`
présent dans un fichier n'annule pas un blocage d'un autre. C'est la raison
d'être de la directive `!#safari_cb_affinity`, et la raison pour laquelle un
produit fini regroupe les listes par catégorie plutôt que d'en charger des
dizaines.

---

## Licences

Chaque liste reste sous la licence de ses auteurs (champ `license` dans
`filters/index.json`). Ce dépôt ne distribue que des conversions.
