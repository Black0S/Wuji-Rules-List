#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
tests.py — non-regression du convertisseur.

Chaque cas correspond a un defaut reellement rencontre, ou a une contrainte
etablie empiriquement par tools/wk_probe.swift sur le compilateur de Safari.

    python3 tests.py
"""

import importlib.util
import json
import os
import sys

ROOT = os.path.dirname(os.path.abspath(__file__))
spec = importlib.util.spec_from_file_location("cw", os.path.join(ROOT, "convert_webkit.py"))
cw = importlib.util.module_from_spec(spec)
spec.loader.exec_module(cw)

FAILURES = []
CASES = [0]


def convert(lines, **kw):
    c = cw.Converter(**kw)
    c.convert_lines(lines if isinstance(lines, list) else [lines])
    body, tail = c.assemble()
    return c, body, tail


def check(name, cond, detail=""):
    CASES[0] += 1
    if not cond:
        FAILURES.append("%s%s" % (name, " — " + detail if detail else ""))


def rules_of(body, kind="block"):
    return [r for r in body if r["action"]["type"] == kind]


# --- traduction des motifs ---------------------------------------------------
c, b, _ = convert("||exemple.com^")
uf = rules_of(b)[0]["trigger"]["url-filter"]
check("ancre ||", uf.startswith("^[htpsw]+://([a-z0-9-]+\\.)*"), uf)
check("separateur ^ final obligatoire", uf.endswith("[/:&?=,;]"), uf)

c, b, _ = convert("||a.com^$third-party,script")
t = rules_of(b)[0]["trigger"]
check("$third-party", t.get("load-type") == ["third-party"])
check("$script", t.get("resource-type") == ["script"])

c, b, _ = convert("||a.com^$subdocument")
t = rules_of(b)[0]["trigger"]
check("$subdocument -> child-frame", t.get("load-context") == ["child-frame"])

c, _, _ = convert("||a.com^$domain=x.com|~y.com")
check("$domain mixte ecarte", any("melange" in k for k in c.skipped))

# --- contraintes WebKit verifiees par la sonde -------------------------------
for line in ("@@||site.com^$document,domain=a.com", "[$path=/x]a.com##.y",
             "*$script,denyallow=cdn.com,domain=s.com"):
    c, b, t = convert(line)
    for r in b + t:
        n = sum(1 for k in ("if-domain", "unless-domain", "if-top-url", "unless-top-url")
                if k in r["trigger"])
        check("une seule condition par trigger", n <= 1, line)

c, b, _ = convert("/ad{2,3}s/")
check("{n,m} developpe exactement", rules_of(b)[0]["trigger"]["url-filter"] == "addd?s",
      str(b))
c, _, _ = convert("/a(?=b)/")
check("lookahead refuse", bool(c.skipped))
c, _, _ = convert("/a^b/")
check("ancre ^ en milieu refusee", any("ancre" in k for k in c.skipped))

# --- reecritures et recuperations -------------------------------------------
c, b, _ = convert(r"/n\d+\.js/")
check("\\d reecrit en [0-9]", "[0-9]" in rules_of(b)[0]["trigger"]["url-filter"])

c, b, _ = convert("/ads(1|2)x/")
check("alternation eclatee", len(rules_of(b)) == 2, str(len(rules_of(b))))
c, _, _ = convert("/(a|b)+/")
check("alternation sous quantificateur refusee", bool(c.skipped))

c, b, _ = convert("flixscans.*##.pub", safari_version=15)
doms = rules_of(b, "css-display-none")[0]["trigger"]["if-domain"]
check("joker de TLD etendu (Safari < 26)", len(doms) > 20, str(len(doms)))

c, b, _ = convert("||p.com^$dnsrewrite=ad-block.dns.adguard.com")
check("$dnsrewrite bloquant -> block", len(rules_of(b)) == 1)
c, _, _ = convert("||p.com^$dnsrewrite=1.2.3.4")
check("$dnsrewrite redirigeant ecarte", bool(c.skipped))

c, b, _ = convert("[$path=/app]tumblr.com##.x")
t = rules_of(b, "css-display-none")[0]["trigger"]
check("$path -> if-top-url", "if-top-url" in t and "/app" in t["if-top-url"][0])

c, b, _ = convert(["*$script,denyallow=cdn.com|jq.com,domain=s.com", "||tard.com^$script"])
kinds = [r["action"]["type"] for r in b]
check("denyallow: blocage puis exceptions", kinds[:4] ==
      ["block", "ignore-previous-rules", "ignore-previous-rules", "block"], str(kinds[:4]))
check("denyallow: groupe atomique", c.atomic and c.atomic[0][1] == 3, str(c.atomic))

# l'exception ne doit lever le blocage que pour ce qui correspond AUSSI au motif
check("denyallow: motif combine au domaine",
      cw.denyallow_patterns("cdn.com", "/banner.png")
      == ["||cdn.com/banner.png", "||cdn.com/*/banner.png"],
      str(cw.denyallow_patterns("cdn.com", "/banner.png")))
check("denyallow: motif generique -> domaine entier",
      cw.denyallow_patterns("cdn.com", "*") == ["||cdn.com^"])
check("denyallow: motif deja ancre -> repli sur le domaine",
      cw.denyallow_patterns("cdn.com", "||autre.com/x") == ["||cdn.com^"])
c, b, _ = convert("/banner.png$image,denyallow=cdn.com,domain=site.org")
exc = [r["trigger"]["url-filter"] for r in b if r["action"]["type"] == "ignore-previous-rules"
       and r["trigger"]["url-filter"] != ".*"]
check("denyallow: exceptions portent le chemin", exc and all("banner" in e for e in exc), str(exc))
c, _, _ = convert("*$script,denyallow=y.com")
check("denyallow generique sans $domain refuse",
      any("generique sans $domain" in k for k in c.skipped))
c, b, _ = convert("||ubuntu.org^$denyallow=autre.com")
check("denyallow sur motif ancre accepte sans $domain", bool(rules_of(b)), str(c.skipped))

c, b, _ = convert(["||ads.com^$third-party", "||ads.com^$third-party,badfilter"])
check("$badfilter applique", not rules_of(b))

# --- profil Safari 26 : if-frame-url et request-method ----------------------
c, b, _ = convert("flixscans.*##.pub")
t = rules_of(b, "css-display-none")[0]["trigger"]
check("joker de TLD -> if-frame-url", "if-frame-url" in t and "flixscans" in t["if-frame-url"][0],
      json.dumps(t)[:90])

c, b, _ = convert("flixscans.*##.pub", safari_version=15)
t = rules_of(b, "css-display-none")[0]["trigger"]
check("Safari 15: repli sur l'expansion de TLD",
      "if-domain" in t and len(t["if-domain"]) > 20, json.dumps(t)[:70])

c, b, _ = convert(r"||b.com^$domain=/^ads[0-9]+\.com$/")
t = rules_of(b)[0]["trigger"]
check("$domain=/regex/ -> if-frame-url", "if-frame-url" in t)
check("regex de domaine: $ final remplace", not t["if-frame-url"][0].endswith("$"),
      t["if-frame-url"][0])

check("alternation dans $domain eclatee",
      len(cw.domain_to_frame_regex("/bad(a|b)/")) == 2)
check("regex de domaine a repetition developpee",
      cw.domain_to_frame_regex("/im{2}possible/")[0].endswith("immpossible"))
check("regex de domaine avec assertion ignoree",
      cw.domain_to_frame_regex("/a(?=b)/") == [])

c, b, _ = convert("||a.com^$method=get")
check("$method -> request-method", rules_of(b)[0]["trigger"].get("request-method") == "get")
c, _, _ = convert("||a.com^$method=~get")
check("$method negatif refuse", bool(c.skipped))
c, _, _ = convert("||a.com^$method=get", safari_version=15)
check("$method refuse sous Safari 26", bool(c.skipped))

for line in ("flixscans.*##.pub", r"||b.com^$domain=/^ads\.com$/"):
    c, b, t = convert(line)
    for r in b + t:
        n = sum(1 for k in ("if-domain", "unless-domain", "if-top-url",
                            "unless-top-url", "if-frame-url", "unless-frame-url")
                if k in r["trigger"])
        check("if-frame-url compte comme condition unique", n <= 1, line)

# --- cosmetique --------------------------------------------------------------
c, b, _ = convert("site.com##div:has(> .ad)")
check(":has() accepte par defaut", len(rules_of(b, "css-display-none")) == 1)
c, _, _ = convert("site.com##div:has-text(pub)")
check(":has-text() ecarte", bool(c.skipped))
c, _, _ = convert("site.com#%#//scriptlet('set-constant','a','b')")
check("scriptlet consigne", len(c.extended["scriptlets"]) == 1)

# Filtrage HTML: un selecteur se consigne, une directive d'en-tete non. Wuji
# recrit le document avant analyse, mais ne recrit aucune en-tete — la
# consigner y mettrait un selecteur qui ne peut rien designer, et un selecteur
# suffit a faire demarrer l'observateur de mutations de la page.
c, _, _ = convert("site.com##^script:has-text(pub)")
check("filtrage HTML consigne", [h["expression"] for h in c.extended["html"]]
      == ["script:has-text(pub)"], repr(c.extended["html"]))
c, _, _ = convert("site.com##^responseheader(location)")
check("##^responseheader() ecarte", not c.extended["html"], repr(c.extended["html"]))

# --- garde document et format hosts -----------------------------------------
c, b, _ = convert("||pub.com^")
guard = [r for r in b if r["action"]["type"] == "ignore-previous-rules"
         and r["trigger"].get("resource-type") == ["document"]]
check("garde navigation principale", len(guard) == 1)

c = cw.Converter()
c.convert_lines(["0.0.0.0 tracker.test", "127.0.0.1 localhost"], hosts_mode=True)
b, _ = c.assemble()
check("format hosts", len(rules_of(b)) == 1)

# --- decoupage des options ---------------------------------------------------
pat, opts = cw.split_options(r"/re\.gif/$domain=/site[0-9]\.com/")
check("regex dans une valeur de modificateur", pat == r"/re\.gif/" and opts.startswith("domain="),
      "%s | %s" % (pat, opts))

# --- validateur interne ------------------------------------------------------
conv = cw.Converter()
try:
    conv.validate({"url-filter": ".*", "if-domain": ["*a.com"], "if-top-url": ["^x"]},
                  {"type": "block"})
    check("validate() refuse deux conditions", False)
except cw.Unsupported:
    CASES[0] += 1

# --- arguments des primitives uBO --------------------------------------------
# Un argument vide garde sa place : le jeter decalait l'adresse en texte de remplacement,
# et la regle YouTube la plus importante s'appliquait a toutes les requetes.
args = cw.parse_bare_args(r'trusted-replace-xhr-response, /"adPlacements.*?"\}{2\,4}\]\,/, , /\/player/')
check("argument vide garde sa place", args == ["trusted-replace-xhr-response",
      '/"adPlacements.*?"\\}{2,4}\\],/', "", "/\\/player/"], repr(args))
args = cw.parse_bare_args("json-prune-fetch-response, adPlacements adSlots, , propsToMatch, /player?")
check("propsToMatch reste une paire nom/valeur", args[2:] == ["", "propsToMatch", "/player?"], repr(args))
check("virgule echappee rendue", cw.parse_bare_args(r'rmnt, script, window\,"fetch"')[2] == 'window,"fetch"')
check("virgule finale sans argument", cw.parse_bare_args("set, a.b, false, ") == ["set", "a.b", "false"])
check("primitive sans argument", cw.parse_bare_args("nowoif") == ["nowoif"])
c, _, _ = convert(["www.youtube.com##+js(trusted-replace-xhr-response, /x/, , /player/)"])
check("argument vide jusque dans l'annexe",
      c.extended["scriptlets"][-1]["args"] == ["/x/", "", "/player/"], repr(c.extended["scriptlets"][-1]))

# --- regex: traduction exacte vers le sous-ensemble WebKit --------------------
def rx(r):
    try:
        return cw.validate_raw_regex(r)
    except cw.Unsupported as e:
        return str(e)

check("(?:) -> ()", rx(r"a(?:b)c") == ["a(b)c"], str(rx(r"a(?:b)c")))
check("paresseux -> gourmand", rx(r"a.*?b+?c??") == ["a.*b+c?"], str(rx(r"a.*?b+?c??")))
check("{n} sur une classe", rx(r"[0-9a-f]{3}\.js") == ["[0-9a-f][0-9a-f][0-9a-f]\\.js"],
      str(rx(r"[0-9a-f]{3}\.js")))
check("{n,} -> n copies puis *", rx(r"x{2,}") == ["xxx*"])
check(".{100,} refuse (fige WebKit)", "trop longue" in rx(r"a\..{100,}"))
check("{0,2} -> optionnels", rx(r"x{0,2}") == ["x?x?"])
check("{n} sur un groupe", rx(r"(ab){2}") == ["(ab)(ab)"])
check("\\D hors classe", rx(r"a\Db") == ["a[^0-9]b"])
check("\\D dans une classe refuse", "classe" in rx(r"[\D-]"))
check("lookahead refuse", "assertion" in rx(r"a(?=b)"))
check("alternation non capturante eclatee", rx(r"\.(?:com|net)/") == ["\\.(com)/", "\\.(net)/"],
      str(rx(r"\.(?:com|net)/")))
check("[\\s\\S] -> .", rx(r"a[\s\S]*b") == ["a.*b"], str(rx(r"a[\s\S]*b")))
check("ancre $ sortie de son groupe", rx(r"\.(js|j$)") == ["\\.(js)", "\\.(j)$"], str(rx(r"\.(js|j$)")))
check("ancre ^ sortie de son groupe", rx(r"(?:^|\.)x/")[0] == "^x/", str(rx(r"(?:^|\.)x/")))
check("parentheses d'une classe gardees", rx(r"a[0-9()]+\.") == ["a[0-9()]+\\."],
      str(rx(r"a[0-9()]+\.")))
check("groupe vide retire", rx(r"a(?:$|\?)") == ["a$", "a(\\?)"], str(rx(r"a(?:$|\?)")))
check("modificateurs: virgule apres une regex",
      cw.split_modifiers("domain=/re{1,2}/,script,3p") == ["domain=/re{1,2}/", "script", "3p"])
check("$domain: regex a alternation non coupee",
      cw.extended_scope.split_pipes("a.com|/(x|y)\\.com/|~b.com") == ["a.com", "/(x|y)\\.com/", "~b.com"])
c, b, _ = convert("*$script,3p,denyallow=cloudflare.com,domain=animesa.*")
bl = rules_of(b)
check("$denyallow borne par un joker de TLD", bl and "if-frame-url" in bl[0]["trigger"]
      and any(r["action"]["type"] == "ignore-previous-rules" for r in b), str(b)[:300])
# --- domaines: TLD seul et `>>` ----------------------------------------------
c, b, _ = convert("ru##.pub-ru")
css = rules_of(b, "css-display-none")
check("TLD seul garde sa portee", css and css[0]["trigger"].get("if-domain") == ["*ru"], str(b))
c, b, _ = convert("site.com>>##.pub")
css = rules_of(b, "css-display-none")
check("uBO site>> lu comme site", css and css[0]["trigger"].get("if-domain") == ["*site.com"], str(b))

# --- annexe: portee exacte, jamais generique ---------------------------------
def ext(lines):
    c = cw.Converter()
    c.convert_lines(lines if isinstance(lines, list) else [lines])
    return c.extended

e = ext("exemple.*##+js(set, a, 1)")
check("annexe: joker garde tel quel", e["scriptlets"][0]["domains"] == ["exemple.*"], str(e["scriptlets"]))
e = ext("ru##div:has-text(pub)")
check("annexe: TLD seul borne la regle", e["procedural"][0]["domains"] == ["ru"], str(e["procedural"]))
e = ext("/^foo[0-9]+\\.com$/##div:has-text(pub)")
check("annexe: regex de domaine gardee", e["procedural"][0]["domains"] == ["/^foo[0-9]+\\.com$/"],
      str(e["procedural"]))
e = ext("*.bad##div:has-text(pub)")
check("annexe: portee illisible -> ecartee, pas generique", e["procedural"] == [], str(e["procedural"]))
e = ext("[$path=/news]site.com##div:has-text(pub)")
p = e["procedural"][0].get("page", "")
import re as _re
check("annexe: $path en condition de page",
      _re.search(p, "https://site.com/news/1") and not _re.search(p, "https://site.com/sport"), p)
e = ext("[$path]site.com#%#//scriptlet('set-constant', 'a', '1')")
p = e["scriptlets"][0].get("page", "")
check("annexe: [$path] seul = accueil",
      _re.search(p, "https://site.com/") and not _re.search(p, "https://site.com/x"), p)
e = ext("[$domain=/tv[0-9]+\\.com/]##.ad")
check("annexe: [$domain=/re/] garde", e["procedural"] and e["procedural"][0]["domains"] == ["/tv[0-9]+\\.com/"],
      str(e))

# --- injection de style -----------------------------------------------------
e = ext("site.com##.nav.sticky {top:0px;}")
check("## sel {decl} -> style", e["styles"] and e["styles"][0]["declarations"] == "top:0px;"
      and e["procedural"] == [], str(e))
e = ext('site.com#$#div[data-x="{a}"] { display: none !important; }')
check("accolade entre guillemets n'est pas une declaration",
      e["styles"] and e["styles"][0]["selector"] == 'div[data-x="{a}"]', str(e["styles"]))
e = ext("site.com##[data-t=\"x\"] {remove:true;}")
check("{remove:true} garde", e["styles"] and "remove" in e["styles"][0]["declarations"], str(e))

# --- exceptions: elles atteignent l'annexe -----------------------------------
e = ext(["site.com##+js(set, a, 1)", "site.com#@#+js(set, a, 1)"])
check("#@#+js consigne en exception",
      any(s["exception"] and s["name"] == "set" for s in e["scriptlets"]), str(e["scriptlets"]))
e = ext(["site.com#@#+js()"])
check("#@#+js() leve tout", e["scriptlets"] and e["scriptlets"][0]["name"] == ""
      and e["scriptlets"][0]["exception"], str(e["scriptlets"]))
e = ext(["site.com#@#div:has-text(x)"])
check("#@# procedural consigne", e["procedural"] and e["procedural"][0]["exception"], str(e))
c, b, _ = convert(["##.pub", "#@#.pub"])
check("#@# sans domaine retire le selecteur partout", not rules_of(b, "css-display-none"), str(b))
c, b, _ = convert(["a.com,~x.a.com##.pub"])
check("inclusion + exclusion -> annexe, pas de masquage sur l'exclu",
      not rules_of(b, "css-display-none") and c.extended["procedural"][0]["excluded"] == ["x.a.com"], str(b))


# --- reseau: ce que WebKit n'applique pas, consigne pour Wuji ------------------
e = ext("||site.com^$csp=worker-src 'none'")
check("$csp consigne pour Wuji", e.get("csp") and e["csp"][0]["policy"] == "worker-src 'none'", str(e.get("csp")))
e = ext("$csp=script-src 'self',domain=a.com|b.com")
check("$csp borne par $domain", e["csp"][0]["domains"] == ["a.com", "b.com"], str(e.get("csp")))
e = ext("||x.com^$redirect=noopjs,script,domain=a.com")
check("$redirect consigne", e["redirects"][0]["resource"] == "noopjs"
      and e["redirects"][0]["types"] == ["script"], str(e.get("redirects")))
c, b, _ = convert("||x.com/ads.js^$script,redirect=noopjs:5")
check("$redirect devient un blocage", rules_of(b) and rules_of(b)[0]["trigger"]["resource-type"] == ["script"], str(b))
c, b, _ = convert("||x.com/ads.js^$script,redirect-rule=noopjs")
check("$redirect-rule ne bloque pas", not rules_of(b), str(b))

e = ext("||disqus.com^$cookie=disqus_unique")
check("$cookie=nom consigne", e["cookies"][0]["name"] == "disqus_unique", str(e.get("cookies")))
e = ext("@@||godaddy.com^$cookie=/^_ga_/")
check("exception $cookie consignee", e["cookies"][0]["exception"], str(e.get("cookies")))
c, b, _ = convert("||x.com^$cookie")
check("$cookie nu reste WebKit", rules_of(b, "block-cookies") and not c.extended.get("cookies"), str(b))
print("%d cas verifies" % CASES[0])
if FAILURES:
    print("\n%d ECHEC(S) :" % len(FAILURES))
    for f in FAILURES:
        print("   %s" % f)
    sys.exit(1)
print("tous les cas passent")
