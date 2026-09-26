// Sonde de comportement: ce que `ignore-previous-rules` annule reellement dans le
// WebKit du systeme, selon sa place et son trigger. C'est elle qui fixe l'ordre
// d'assemblage de convert_webkit.py (Converter.convert_partial_exception).
//
// Usage: swift tools/wk_generichide.swift
//
// La page de test porte trois blocs — #gen (cosmetique generique), #spe
// (cosmetique propre au site) — et une requete vers example.org/pub.js que la
// regle reseau bloque. Le temoin, sans la regle reseau, dit ce que vaut la
// requete sans blocage: hors ligne, elle echoue aussi, et la sonde le signale.
import AppKit
import WebKit

typealias Rule = [String: Any]
let site = #"^[htpsw]+://([a-z0-9-]+\.)*example\.org[/:&?=,;]"#
let ignore: [String: Any] = ["type": "ignore-previous-rules"]
let generic: Rule = ["trigger": ["url-filter": ".*"], "action": ["type": "css-display-none", "selector": "#gen"]]
let block: Rule = ["trigger": ["url-filter": #"pub\.js"#], "action": ["type": "block"]]
let guardRule: Rule = ["trigger": ["url-filter": ".*", "resource-type": ["document"], "load-context": ["top-frame"]], "action": ignore]
let specific: Rule = ["trigger": ["url-filter": ".*", "if-domain": ["*example.org"]], "action": ["type": "css-display-none", "selector": "#spe"]]
func ghide(documentOnly: Bool = false) -> Rule {
    var trigger: [String: Any] = ["url-filter": ".*", "if-top-url": [site]]
    if documentOnly { trigger["resource-type"] = ["document"] }
    return ["trigger": trigger, "action": ignore]
}

// (nom, regles, attendu sur example.org: gen masque ?, spe masque ?, reseau bloque ?)
let cases: [(String, [Rule], (Bool, Bool, Bool))] = [
    ("temoin sans blocage", [generic, guardRule, specific], (true, true, false)),
    ("ancien: exception en fin", [generic, block, guardRule, specific, ghide()], (false, false, false)),
    ("nouveau: generique, exception, reseau", [generic, ghide(), block, guardRule, specific], (false, true, true)),
    ("exception restreinte a document", [generic, ghide(documentOnly: true), block, guardRule, specific], (true, true, true)),
]

let html = """
<div id=gen>gen</div><div id=spe>spe</div>
<script>fetch('https://www.example.org/pub.js').then(() => document.title = 'passe', () => document.title = 'bloque')</script>
"""

final class Probe: NSObject, WKNavigationDelegate {
    var index = 0
    var view: WKWebView?
    let store = WKContentRuleListStore(url: URL(fileURLWithPath: NSTemporaryDirectory())
        .appendingPathComponent("wkghide-\(UUID().uuidString)"))!
    var failures = 0

    func next() {
        guard index < cases.count else { exit(failures == 0 ? 0 : 1) }
        let (_, rules, _) = cases[index]
        store.compileContentRuleList(forIdentifier: "c\(index)", encodedContentRuleList: String(data: try! JSONSerialization.data(withJSONObject: rules), encoding: .utf8)!) { list, error in
            guard let list else { print("REFUSE", error ?? ""); exit(2) }
            let config = WKWebViewConfiguration()
            config.websiteDataStore = .nonPersistent()
            config.userContentController.add(list)
            let view = WKWebView(frame: .init(x: 0, y: 0, width: 200, height: 200), configuration: config)
            view.navigationDelegate = self
            self.view = view
            view.loadHTMLString(html, baseURL: URL(string: "https://www.example.org/")!)
        }
    }

    func webView(_ webView: WKWebView, didFinish navigation: WKNavigation!) {
        DispatchQueue.main.asyncAfter(deadline: .now() + 1.5) {
            let js = "[getComputedStyle(gen).display, getComputedStyle(spe).display, document.title].join(' ')"
            webView.evaluateJavaScript(js) { value, _ in
                let parts = (value as? String ?? "").split(separator: " ").map(String.init)
                let got = (parts[0] == "none", parts[1] == "none", parts.count > 2 && parts[2] == "bloque")
                let (name, _, want) = cases[self.index]
                let ok = got == want
                if !ok { self.failures += 1 }
                print(ok ? "ok   " : "ECART", name, "— generique masque:", got.0, "specifique masque:", got.1, "reseau bloque:", got.2)
                self.index += 1
                self.next()
            }
        }
    }
}

let app = NSApplication.shared
let probe = Probe()
probe.next()
DispatchQueue.main.asyncAfter(deadline: .now() + 60) { print("delai depasse"); exit(3) }
app.run()
