#!/usr/bin/env python3
"""Refait sources.json a partir du catalogue d'uBlock Origin.

    python3 tools/ubo_catalog.py                      # assets.json d'uBO, en ligne
    python3 tools/ubo_catalog.py chemin/assets.json   # une copie locale

**Les listes d'uBO, et elles seules.** Le depot proposait cent soixante listes de quinze
mainteneurs, ecrites dans trois dialectes — celui d'uBO, celui d'AdGuard, celui des fichiers
hosts. Chaque dialecte demandait sa traduction, et chaque traduction ses ecarts. uBO publie
le catalogue que ses propres utilisateurs choisissent; il est le plus suivi, c'est lui que
Wuji reproduit, et ses listes sont toutes lisibles par uBO — y compris celles d'AdGuard, qu'il
prend dans la version qu'AdGuard compile pour lui (`filters.adtidy.org/extension/ublock/`).

**Les identifiants de Wuji sont gardes.** Une liste qui existait deja sous un autre nom le
garde: Wuji la reconnait, et une installation existante passe a la version d'uBO par une
simple mise a jour au lieu de disparaitre. Les autres prennent `ubo-<cle>`.

Ce script ne telecharge aucune liste: il ecrit sources.json, que fetch_filters.py lit.
"""
import json
import os
import sys
import urllib.request

RACINE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SOURCES = os.path.join(RACINE, "sources.json")
ASSETS = "https://raw.githubusercontent.com/gorhill/uBlock/master/assets/assets.json"

# Cle d'uBO -> identifiant deja publie par ce depot pour la meme liste.
IDENTIFIANTS = {
    "ublock-filters": "ublock-origin",
    "ublock-badware": "ublock-origin-badware-risks",
    "ublock-privacy": "ublock-origin-privacy",
    "ublock-unbreak": "ublock-origin-unbreak",
    "ublock-quick-fixes": "ublock-origin-quick-fixes",
    "ublock-annoyances": "ublock-origin-annoyances",
    "ublock-cookies-adguard": "ublock-origin-cookie-notices",
    "block-lan": "ublock-origin-block-outsider-intrusion-into-lan",
    "easylist": "easylist",
    "easyprivacy": "easyprivacy",
    "fanboy-cookiemonster": "easylist-cookie",
    "fanboy-social": "fanboy-social-blocking",
    "fanboy-thirdparty_social": "fanboy-anti-facebook",
    "adguard-generic": "adguard-base",
    "adguard-mobile": "adguard-mobile-ads",
    "adguard-cookies": "adguard-cookie-notices",
    "adguard-social": "adguard-social-media",
    "adguard-popup-overlays": "adguard-popups",
    "adguard-mobile-app-banners": "adguard-mobile-app-banners",
    "adguard-other-annoyances": "adguard-other-annoyances",
    "adguard-widgets": "adguard-widgets",
    "urlhaus-1": "urlhaus-online",
    "plowe-0": "peter-lowe-adservers",
    "ara-0": "liste-ar",
    "BGR-0": "bulgarian",
    "CHN-0": "adguard-chinese",
    "CZE-0": "easylist-czech-and-slovak",
    "DEU-0": "easylist-germany",
    "FRA-0": "adguard-french",
    "IND-0": "indianlist",
    "ISR-0": "easylist-hebrew",
    "ITA-0": "easylist-italy",
    "JPN-1": "adguard-japanese",
    "LTU-0": "easylist-lithuania",
    "LVA-0": "latvian",
    "NLD-0": "adguard-dutch",
    "RUS-0": "ru-adlist-for-ubo",
    "spa-0": "easylist-spanish",
    "spa-1": "adguard-spanish-portuguese",
    "TUR-0": "adguard-turkish",
    "UKR-0": "adguard-ukrainian",
}

# Les groupes d'uBO, dans son ordre, nommes comme Wuji les affiche.
GROUPES = [
    ("default", "uBlock Origin"),
    ("ads", "Publicités"),
    ("privacy", "Confidentialité"),
    ("malware", "Sites malveillants"),
    ("multipurpose", "Polyvalentes"),
    ("annoyances", "Nuisances"),
    ("regions", "Régions"),
]


def adresse(entree):
    """La premiere adresse en ligne: uBO range apres elle ses copies embarquees."""
    urls = entree.get("contentURL")
    urls = [urls] if isinstance(urls, str) else (urls or [])
    for u in urls:
        if u.startswith("https://") or u.startswith("http://"):
            return u
    return None


def main():
    source = sys.argv[1] if len(sys.argv) > 1 else ASSETS
    if source.startswith("http"):
        with urllib.request.urlopen(source, timeout=60) as reponse:
            assets = json.load(reponse)
    else:
        assets = json.load(open(source, encoding="utf-8"))

    ancien = json.load(open(SOURCES, encoding="utf-8"))
    groupes = {cle: {"id": cle, "maintainer": nom, "homepage": "https://github.com/gorhill/uBlock",
                     "lists": []} for cle, nom in GROUPES}
    vues = set()
    for cle, entree in assets.items():
        if entree.get("content") != "filters":
            continue
        url = adresse(entree)
        groupe = groupes.get(entree.get("group"))
        if not url or groupe is None:
            print("  ! ignoree: %s" % cle)
            continue
        liste = {
            "id": IDENTIFIANTS.get(cle, "ubo-" + cle.lower()),
            "name": entree.get("title", cle),
            "url": url,
            "ubo": cle,
        }
        if entree.get("supportURL"):
            liste["homepage"] = entree["supportURL"]
        if entree.get("lang"):
            liste["languages"] = entree["lang"].split()
        if not entree.get("off", False):
            liste["tags"] = ["ubo-default"]
        # uBO range le meme fichier sous deux cles (les cookies d'AdGuard et d'EasyList
        # recopies par uBO): une seule entree, la premiere.
        if url in vues:
            continue
        vues.add(url)
        groupe["lists"].append(liste)

    ancien["$comment"] = (
        "Genere par tools/ubo_catalog.py depuis le catalogue d'uBlock Origin "
        "(assets/assets.json): ses listes, ses adresses, ses groupes, et rien d'autre. "
        "Ne pas modifier a la main: relancer le script. `ubo` porte la cle de la liste chez uBO; "
        "`tags: [ubo-default]` marque celles qu'uBO active d'office.")
    ancien["groups"] = [g for g in (groupes[c] for c, _ in GROUPES) if g["lists"]]
    ancien.pop("$comment_covered_by", None)
    with open(SOURCES, "w", encoding="utf-8") as fh:
        json.dump(ancien, fh, ensure_ascii=False, indent=2)
        fh.write("\n")
    total = sum(len(g["lists"]) for g in ancien["groups"])
    print("%d listes d'uBO en %d groupes -> sources.json" % (total, len(ancien["groups"])))


if __name__ == "__main__":
    main()
