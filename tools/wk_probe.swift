// Sonde de conformite: interroge le compilateur de content blocker de WebKit
// du systeme (celui de Safari) pour etablir ce qu'il accepte reellement.
// Usage: swift tools/wk_probe.swift
import WebKit
import Foundation

let dir = URL(fileURLWithPath: NSTemporaryDirectory())
    .appendingPathComponent("wkprobe-\(UUID().uuidString)")
try? FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
guard let store = WKContentRuleListStore(url: dir) else { fatalError("store") }

var pending = 0, idx = 0
var results: [(Int, String, String, String)] = []

func t(_ section: String, _ label: String, _ json: String) {
    idx += 1; let n = idx; pending += 1
    store.compileContentRuleList(forIdentifier: "p\(n)", encodedContentRuleList: json) { list, err in
        var r = "OK"
        if let e = err as NSError? {
            let h = (e.userInfo["NSHelpAnchor"] as? String) ?? e.localizedDescription
            r = "REFUSE: " + h.replacingOccurrences(of: "Rule list compilation failed: ", with: "")
        } else if list == nil { r = "OK (liste vide)" }
        results.append((n, section, label, r))
        pending -= 1
    }
}

func rule(_ trigger: String, _ action: String = #"{"type":"block"}"#) -> String {
    return "[{\"trigger\":\(trigger),\"action\":\(action)}]"
}

// ---- 1. Conditions du trigger ------------------------------------------------
t("conditions", "if-domain seul", rule(#"{"url-filter":".*","if-domain":["*a.com"]}"#))
t("conditions", "unless-domain seul", rule(#"{"url-filter":".*","unless-domain":["*a.com"]}"#))
t("conditions", "if-top-url seul", rule(#"{"url-filter":".*","if-top-url":["^https?://a\\.com"]}"#))
t("conditions", "unless-top-url seul", rule(#"{"url-filter":".*","unless-top-url":["^https?://a\\.com"]}"#))
t("conditions", "if-domain + unless-domain", rule(#"{"url-filter":".*","if-domain":["*a.com"],"unless-domain":["*b.com"]}"#))
t("conditions", "if-domain + if-top-url", rule(#"{"url-filter":".*","if-domain":["*a.com"],"if-top-url":["^https?://b\\.com"]}"#))
t("conditions", "if-domain + unless-top-url", rule(#"{"url-filter":".*","if-domain":["*a.com"],"unless-top-url":["^https?://b\\.com"]}"#))
t("conditions", "if-top-url + unless-top-url", rule(#"{"url-filter":".*","if-top-url":["^https?://a\\.com"],"unless-top-url":["^https?://b\\.com"]}"#))

// ---- 2. Domaines -------------------------------------------------------------
t("domaines", "domaine sans etoile", rule(#"{"url-filter":".*","if-domain":["a.com"]}"#))
t("domaines", "domaine avec etoile", rule(#"{"url-filter":".*","if-domain":["*a.com"]}"#))
t("domaines", "domaine majuscules", rule(#"{"url-filter":".*","if-domain":["*A.com"]}"#))
t("domaines", "domaine punycode", rule(#"{"url-filter":".*","if-domain":["*xn--exmple-cua.com"]}"#))
t("domaines", "domaine unicode brut", rule(#"{"url-filter":".*","if-domain":["*exémple.com"]}"#))
t("domaines", "tableau vide", rule(#"{"url-filter":".*","if-domain":[]}"#))
t("domaines", "etoile seule", rule(#"{"url-filter":".*","if-domain":["*"]}"#))

// ---- 3. resource-type / load-type / load-context ------------------------------
t("types", "tous types modernes", rule(#"{"url-filter":".*","resource-type":["document","image","style-sheet","script","font","media","popup","fetch","websocket","ping","other","svg-document"]}"#))
t("types", "raw (legacy)", rule(#"{"url-filter":".*","resource-type":["raw"]}"#))
t("types", "type inconnu", rule(#"{"url-filter":".*","resource-type":["xhr"]}"#))
t("types", "resource-type vide", rule(#"{"url-filter":".*","resource-type":[]}"#))
t("types", "load-type first+third", rule(#"{"url-filter":".*","load-type":["first-party","third-party"]}"#))
t("types", "load-context child-frame", rule(#"{"url-filter":".*","load-context":["child-frame"]}"#))
t("types", "load-context inconnu", rule(#"{"url-filter":".*","load-context":["sub-frame"]}"#))

// ---- 4. url-filter -----------------------------------------------------------
t("url-filter", "absent", "[{\"trigger\":{},\"action\":{\"type\":\"block\"}}]")
t("url-filter", "chaine vide", rule(#"{"url-filter":""}"#))
t("url-filter", "classe negative [^/]", rule(#"{"url-filter":"^https?://[^/]*\\.ads\\.com"}"#))
t("url-filter", "groupe repete (x)*", rule(#"{"url-filter":"^http://(a\\.)*b\\.com"}"#))
t("url-filter", "groupe optionnel (x)?", rule(#"{"url-filter":"^http://(www\\.)?b\\.com"}"#))
t("url-filter", "ancre $ finale", rule(#"{"url-filter":"ads\\.js$"}"#))
t("url-filter", "^ en milieu", rule(#"{"url-filter":"a^b"}"#))
t("url-filter", "non-ASCII", rule(#"{"url-filter":"publicité"}"#))
t("url-filter", "percent-encode", rule(#"{"url-filter":"publicit%C3%A9"}"#))
t("url-filter", "case-sensitive true", rule(#"{"url-filter":"Ads","url-filter-is-case-sensitive":true}"#))
t("url-filter", "classe [a-z0-9-]", rule(#"{"url-filter":"[a-z0-9-]+\\.com"}"#))
t("url-filter", "lookahead (?=x)", rule(#"{"url-filter":"a(?=b)"}"#))
t("url-filter", "backreference \\1", rule(#"{"url-filter":"(a)\\1"}"#))

// ---- 5. Selecteurs CSS -------------------------------------------------------
func css(_ sel: String) -> String {
    return rule(#"{"url-filter":".*"}"#, "{\"type\":\"css-display-none\",\"selector\":\"\(sel)\"}")
}
t("css", ":has()", css("div:has(> .ad)"))
t("css", ":has() imbrique", css(".x:has(.y:not(.z))"))
t("css", ":is()", css(":is(.a, .b) .ad"))
t("css", ":where()", css(":where(.a) .ad"))
t("css", ":nth-child(2n+1)", css("li:nth-child(2n+1)"))
t("css", "::before pseudo-element", css("div::before"))
t("css", "attribut avec accent", css("[title=\\\"Publicité\\\"]"))
t("css", "combinateurs > + ~", css("a > b + c ~ d"))
t("css", "selecteur invalide", css("div[[["))
t("css", "melange valide/invalide", "[{\"trigger\":{\"url-filter\":\".*\"},\"action\":{\"type\":\"css-display-none\",\"selector\":\".ok\"}},{\"trigger\":{\"url-filter\":\".*\"},\"action\":{\"type\":\"css-display-none\",\"selector\":\"div[[[\"}}]")
t("css", "250 selecteurs groupes", css((1...250).map { ".ad-\($0)" }.joined(separator: ", ")))

// ---- 6. Actions --------------------------------------------------------------
t("actions", "make-https", rule(#"{"url-filter":"^http://a\\.com"}"#, #"{"type":"make-https"}"#))
t("actions", "block-cookies", rule(#"{"url-filter":"a\\.com"}"#, #"{"type":"block-cookies"}"#))
t("actions", "action inconnue", rule(#"{"url-filter":"a\\.com"}"#, #"{"type":"block-everything"}"#))
t("actions", "css-display-none sans selector", rule(#"{"url-filter":".*"}"#, #"{"type":"css-display-none"}"#))

// ---- 7. Divers ---------------------------------------------------------------
t("divers", "cle trigger inconnue", rule(#"{"url-filter":".*","if-frame-url":["a"]}"#))
t("divers", "tableau vide global", "[]")
t("divers", "doublons identiques", "[{\"trigger\":{\"url-filter\":\"a\\\\.com\"},\"action\":{\"type\":\"block\"}},{\"trigger\":{\"url-filter\":\"a\\\\.com\"},\"action\":{\"type\":\"block\"}}]")

while pending > 0 { RunLoop.current.run(mode: .default, before: Date(timeIntervalSinceNow: 0.05)) }
var last = ""
for (_, sec, label, r) in results.sorted(by: { $0.0 < $1.0 }) {
    if sec != last { print("\n--- \(sec) ---"); last = sec }
    let pad = String(repeating: " ", count: max(0, 30 - label.count))
    print("  \(label)\(pad)\(r)")
}
try? FileManager.default.removeItem(at: dir)
