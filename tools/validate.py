#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
tools/validate.py — controle structurel portable des fichiers produits.

`make verify` compile chaque fichier avec le WebKit du systeme, mais n'existe
que sur macOS. Ce script rejoue en Python les contraintes que la sonde a
etablies, pour que la CI attrape les memes defauts partout.

    python3 tools/validate.py            # sur webkit-rules/
    python3 tools/validate.py --dir X    # ailleurs
"""

import argparse
import collections
import glob
import json
import os
import sys

TRIGGER_KEYS = frozenset((
    "url-filter", "url-filter-is-case-sensitive", "if-domain", "unless-domain",
    "if-top-url", "unless-top-url", "if-frame-url", "unless-frame-url",
    "resource-type", "load-type", "load-context", "request-method"))
ACTIONS = frozenset((
    "block", "block-cookies", "css-display-none", "ignore-previous-rules", "make-https"))
RESOURCE = frozenset((
    "document", "image", "style-sheet", "script", "font", "media", "popup",
    "raw", "svg-document", "fetch", "websocket", "ping", "other"))
CONDITIONS = ("if-domain", "unless-domain", "if-top-url", "unless-top-url",
              "if-frame-url", "unless-frame-url")
HTTP_METHODS = frozenset((
    "get", "head", "options", "trace", "put", "delete", "post", "patch", "connect"))
BAD_REGEX = ("{", "}", "(?", "\\d", "\\w", "\\s", "\\D", "\\W", "\\S",
             "\\b", "\\B", "*?", "+?", "??", "|")
WEBKIT_MAX_RULES = 150000


def misplaced_anchor(rx):
    if "^" not in rx[1:] and not ("$" in rx and not rx.endswith("$")):
        return False
    i, in_class, esc = 0, False, False
    while i < len(rx):
        c = rx[i]
        if esc:
            esc = False
        elif c == "\\":
            esc = True
        elif in_class:
            if c == "]":
                in_class = False
        elif c == "[":
            in_class = True
        elif c == "^" and i != 0:
            return True
        elif c == "$" and i != len(rx) - 1:
            return True
        i += 1
    return False


def check_file(path, errors):
    def fail(reason):
        errors["%s : %s" % (os.path.basename(path), reason)] += 1

    try:
        with open(path, "r", encoding="utf-8") as fh:
            rules = json.load(fh)
    except Exception as e:  # noqa: BLE001
        fail("JSON illisible (%s)" % type(e).__name__)
        return 0
    if not isinstance(rules, list) or not rules:
        fail("tableau vide (WebKit refuse: Empty extension)")
        return 0
    if len(rules) > WEBKIT_MAX_RULES:
        fail("%d regles > %d" % (len(rules), WEBKIT_MAX_RULES))

    for rule in rules:
        trigger, action = rule.get("trigger"), rule.get("action")
        if not isinstance(trigger, dict) or not isinstance(action, dict):
            fail("regle malformee"); continue
        if not TRIGGER_KEYS.issuperset(trigger):
            fail("cle de trigger inconnue")
        uf = trigger.get("url-filter")
        if not uf or not isinstance(uf, str):
            fail("url-filter manquant"); continue
        if not uf.isascii():
            fail("url-filter non-ASCII")
        if any(tok in uf for tok in BAD_REGEX):
            fail("regex hors du sous-ensemble WebKit")
        if misplaced_anchor(uf):
            fail("ancre ^ ou $ mal placee")
        present = [k for k in CONDITIONS if k in trigger]
        if len(present) > 1:
            fail("conditions multiples (%s)" % ",".join(present))
        for key in present:
            if not trigger[key]:
                fail("condition %s vide" % key)
        for key in ("if-domain", "unless-domain"):
            for dom in trigger.get(key, ()):
                if not dom.isascii() or dom != dom.lower():
                    fail("domaine non normalise"); break
        for key in ("if-top-url", "unless-top-url", "if-frame-url", "unless-frame-url"):
            for rx in trigger.get(key, ()):
                if not rx or not rx.isascii() or misplaced_anchor(rx) \
                        or any(t in rx for t in BAD_REGEX):
                    fail("regex %s invalide" % key)
        rt = trigger.get("resource-type")
        if rt and not RESOURCE.issuperset(rt):
            fail("resource-type invalide")
        lt = trigger.get("load-type")
        if lt and not {"first-party", "third-party"}.issuperset(lt):
            fail("load-type invalide")
        lc = trigger.get("load-context")
        if lc and not {"top-frame", "child-frame"}.issuperset(lc):
            fail("load-context invalide")
        rm = trigger.get("request-method")
        if rm is not None and rm not in HTTP_METHODS:
            fail("request-method invalide")
        kind = action.get("type")
        if kind not in ACTIONS:
            fail("action invalide")
        elif kind == "css-display-none" and not action.get("selector"):
            fail("css-display-none sans selecteur")
    return len(rules)


def main():
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[1])
    ap.add_argument("--dir", default=os.path.join(
        os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "webkit-rules"))
    args = ap.parse_args()

    files = sorted(glob.glob(os.path.join(args.dir, "Webkit-*.json")))
    if not files:
        print("Aucun fichier a valider dans %s" % args.dir, file=sys.stderr)
        return 1
    errors = collections.Counter()
    total = sum(check_file(f, errors) for f in files)

    print("%d fichiers, %s regles verifiees"
          % (len(files), format(total, ",").replace(",", " ")))
    if errors:
        print("\n%d probleme(s) :" % sum(errors.values()))
        for msg, count in errors.most_common(20):
            print("   %4d  %s" % (count, msg))
        return 1
    print("aucun defaut structurel")
    return 0


if __name__ == "__main__":
    sys.exit(main())
