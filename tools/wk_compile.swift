// Compile chaque fichier de regles avec le compilateur de content blocker de
// WebKit du systeme — celui-la meme qu'utilise Safari. C'est la seule
// verification qui fasse autorite: la validation Python ne fait qu'approcher
// ces contraintes.
//
// Usage:   swift tools/wk_compile.swift webkit-rules/Webkit-*.json
// Sortie:  une ligne par fichier, code de retour 1 si un fichier echoue.
import WebKit
import Foundation

let files = Array(CommandLine.arguments.dropFirst())
if files.isEmpty {
    FileHandle.standardError.write("usage: wk_compile.swift <fichier.json>...\n".data(using: .utf8)!)
    exit(2)
}

let dir = URL(fileURLWithPath: NSTemporaryDirectory())
    .appendingPathComponent("wkcompile-\(UUID().uuidString)")
try? FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
guard let store = WKContentRuleListStore(url: dir) else { fatalError("store indisponible") }

var failures = 0
let quiet = ProcessInfo.processInfo.environment["WK_QUIET"] == "1"

for (i, path) in files.enumerated() {
    let name = (path as NSString).lastPathComponent
    guard let json = try? String(contentsOfFile: path, encoding: .utf8) else {
        print("  ECHEC  \(name) — illisible"); failures += 1; continue
    }
    var done = false, message: String? = nil
    store.compileContentRuleList(forIdentifier: "c\(i)", encodedContentRuleList: json) { _, err in
        if let e = err as NSError? {
            message = ((e.userInfo["NSHelpAnchor"] as? String) ?? e.localizedDescription)
                .replacingOccurrences(of: "Rule list compilation failed: ", with: "")
        }
        done = true
    }
    while !done { RunLoop.current.run(mode: .default, before: Date(timeIntervalSinceNow: 0.02)) }

    if let m = message {
        print("  ECHEC  \(name) — \(m)")
        failures += 1
    } else if !quiet {
        print("  ok     \(name)")
    }
    var removed = false
    store.removeContentRuleList(forIdentifier: "c\(i)") { _ in removed = true }
    while !removed { RunLoop.current.run(mode: .default, before: Date(timeIntervalSinceNow: 0.02)) }
}

try? FileManager.default.removeItem(at: dir)
print(String(repeating: "-", count: 56))
print("\(files.count - failures)/\(files.count) fichiers compiles par WebKit"
      + (failures > 0 ? " — \(failures) EN ECHEC" : ""))
exit(failures > 0 ? 1 : 0)
