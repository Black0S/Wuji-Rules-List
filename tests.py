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

c, b, _ = convert("flixscans.*##.pub")
doms = rules_of(b, "css-display-none")[0]["trigger"]["if-domain"]
check("joker de TLD etendu", len(doms) > 20, str(len(doms)))

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

c, b, _ = convert(["||ads.com^$third-party", "||ads.com^$third-party,badfilter"])
check("$badfilter applique", not rules_of(b))

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
