# -*- coding: utf-8 -*-
"""
extended_network.py — les regles reseau que WebKit compile mais n'applique pas.

**Mesure avant d'ecrire.** Le compilateur de WebKit accepte l'action `redirect`
(vers une URL, ou `transform` qui retire des parametres) — puis ne l'applique
pas dans un WKWebView d'application: la sonde a charge la meme page avec et sans
la regle, la requete est partie intacte. Elle n'existe que pour les extensions
Safari. Trois familles de regles en dependaient:

- `$redirect=ressource` bloque ET remplace la reponse par une ressource neutre.
  Le blocage, WebKit le fait: la regle devient un `block` — c'est la semantique
  d'uBO, ou `$redirect` implique le blocage. Le remplacement, Wuji le rejoue
  dans la page (un substitut de script, une reponse vide a `fetch`): il lit
  l'entree `redirects` de l'annexe.
- `$redirect-rule` ne remplace que ce qu'une autre regle bloque deja: annexe
  seulement.
- `$removeparam` et `$urlskip` touchent l'URL: Wuji les applique aux
  navigations, la ou se joue le pistage — entrees `removeparams` et `urlskips`.
- `$csp` ajoute une politique de securite a la reponse: aucune en-tete ne se
  reecrit dans WebKit, mais une balise `<meta>` posee dans `<head>` a sa
  creation restreint la page de la meme facon (mesure: `script-src 'none'`
  y bloque les scripts qui suivent) — entree `csp`.
- `$cookie=nom` retire un cookie precis; WebKit ne sait retirer que tous les
  cookies d'une requete. Wuji les retire de son magasin — entree `cookies`.
"""

import extended_scope

# Ce qui borne une regle reseau et que Wuji sait relire. Tout autre
# modificateur (`$to`, `$method`, `$header`...) la rend illisible: on ne la
# consigne pas plutot que de l'elargir.
TYPES = {
    "script": "script", "image": "image", "stylesheet": "stylesheet", "css": "stylesheet",
    "xmlhttprequest": "xhr", "xhr": "xhr", "fetch": "xhr", "media": "media",
    "font": "font", "subdocument": "frame", "frame": "frame", "document": "document",
    "doc": "document", "object": "object", "ping": "ping", "websocket": "websocket",
    "other": "other", "popup": "popup",
}
PARTY = {"third-party", "3p", "first-party", "1p", "strict3p", "strict1p"}
HARMLESS = {"important", "all", "match-case", "badfilter"}
FAMILIES = ("redirect", "redirect-rule", "removeparam", "queryprune", "urlskip", "csp", "cookie")


def family_of(mods):
    """Le premier modificateur `redirect`, `removeparam`… et sa valeur."""
    for mod in mods:
        name, _, value = mod.lstrip("~").partition("=")
        name = name.strip().lower()
        if name in FAMILIES:
            return ("removeparam" if name == "queryprune" else name), value.strip()
    return None, None


def entry(pattern, mods, exception):
    """La portee commune: `url`, `domains`, `excluded`, `types`, `party`.
    Rend None si un modificateur n'est pas relisible."""
    domains, types, party = "", [], None
    for mod in mods:
        neg = mod.startswith("~")
        name, _, value = (mod[1:] if neg else mod).partition("=")
        name = name.strip().lower()
        if name in FAMILIES or name in HARMLESS:
            continue
        if name in ("domain", "from"):
            domains = value
        elif name in TYPES:
            if neg:
                return None      # `~script`: rare, et l'inverse ne se dit pas en liste
            types.append(TYPES[name])
        elif name in PARTY:
            third = name in ("third-party", "3p", "strict3p")
            party = "first" if third == neg else "third"
        else:
            return None
    try:
        # Par le prefixe `domain=`: la liste s'y decoupe sans couper une regex.
        portee = extended_scope.scope("", "domain=" + domains if domains else "")
    except extended_scope.ScopeError:
        return None
    out = dict(portee, url=extended_scope.pattern_to_js(pattern.strip() or "*"),
               exception=exception)
    if types:
        out["types"] = sorted(set(types))
    if party:
        out["party"] = party
    return out


def capture(extended, pattern, mods, exception):
    """Consigne la regle si elle appartient a une des trois familles.

    Rend (famille, valeur) pour que l'appelant decide du sort WebKit: seul un
    `$redirect` qui n'est pas une exception devient un blocage."""
    family, value = family_of(mods)
    if not family:
        return None, None
    # `$cookie` sans valeur: WebKit le fait lui-meme (`block-cookies`). `;maxAge=`
    # raccourcit la vie d'un cookie au lieu de le retirer: rien a quoi le ramener.
    if family == "cookie" and ((not value and not exception) or ";" in value):
        return family, value
    e = entry(pattern, mods, exception)
    if e is None:
        return family, value
    if family in ("redirect", "redirect-rule"):
        # `noopjs:5`: la priorite d'uBO ne change rien au substitut.
        e["resource"] = value.split(":")[0].strip()
        e["rule"] = family == "redirect-rule"
        extended.setdefault("redirects", []).append(e)
    elif family == "csp":
        # Une politique ne vaut que pour un document: Wuji la pose dans la page
        # par une balise `<meta>`, mesuree efficace dans WebKit.
        if set(e.get("types", ["document"])) - {"document", "frame"}:
            return family, value
        e["policy"] = value
        extended.setdefault("csp", []).append(e)
    elif family == "cookie":
        # Wuji retire du magasin, apres chaque page, les cookies que la liste
        # nomme: `name` exact, ou `/re/` sur le nom.
        e["name"] = value
        extended.setdefault("cookies", []).append(e)
    elif family == "removeparam":
        e["param"] = value
        extended.setdefault("removeparams", []).append(e)
    else:
        e["steps"] = value
        extended.setdefault("urlskips", []).append(e)
    return family, value
