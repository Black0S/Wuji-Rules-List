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

c, _, _ = convert("/ad{2,3}s/")
check("{n,m} refuse", bool(c.skipped))
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
check("regex de domaine non supportee ignoree",
      cw.domain_to_frame_regex("/im{2}possible/") == [])

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

print("%d cas verifies" % CASES[0])
if FAILURES:
    print("\n%d ECHEC(S) :" % len(FAILURES))
    for f in FAILURES:
        print("   %s" % f)
    sys.exit(1)
print("tous les cas passent")
