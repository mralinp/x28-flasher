// The native window of X28 Flasher: starts the backend (the x28-flasher binary next to this one) and shows its page in a
// WKWebView, so there is no browser. Closing the window or quitting stops the backend; the page's Quit button does too.
import Cocoa
import WebKit

struct Running: Decodable { let pid: Int32; let port: Int; let token: String }

let home = FileManager.default.homeDirectoryForCurrentUser
let runFile = home.appendingPathComponent(".x28-flasher/running.json")

func readRunning() -> Running? {
    guard let data = try? Data(contentsOf: runFile), let r = try? JSONDecoder().decode(Running.self, from: data), kill(r.pid, 0) == 0 else { return nil }
    return r
}

final class AppDelegate: NSObject, NSApplicationDelegate, WKUIDelegate {
    var window: NSWindow!
    var web: WKWebView!
    var backend: Process?
    var loaded = false

    func applicationDidFinishLaunching(_ note: Notification) {
        buildMenu()
        if readRunning() == nil { startBackend() }
        let config = WKWebViewConfiguration()
        web = WKWebView(frame: .zero, configuration: config)
        web.uiDelegate = self
        web.setValue(false, forKey: "drawsBackground")
        window = NSWindow(contentRect: NSRect(x: 0, y: 0, width: 1280, height: 860), styleMask: [.titled, .closable, .miniaturizable, .resizable],
                          backing: .buffered, defer: false)
        window.title = "X28 Flasher"
        window.contentView = web
        window.backgroundColor = NSColor(name: nil) { a in  // follows the system: the page's own --bg in dark and light
            a.bestMatch(from: [.darkAqua, .aqua]) == .darkAqua ? NSColor(red: 0.051, green: 0.059, blue: 0.075, alpha: 1) : NSColor(red: 0.957, green: 0.965, blue: 0.976, alpha: 1)
        }
        window.center()
        window.setFrameAutosaveName("X28FlasherWindow")
        window.makeKeyAndOrderFront(nil)
        NSApp.activate(ignoringOtherApps: true)
        web.loadHTMLString("<style>:root{color-scheme:light dark}@media(prefers-color-scheme:dark){body{background:#0d0f13;color:#9aa3b2}}@media(prefers-color-scheme:light){body{background:#f4f6f9;color:#586274}}</style><body style='font:14px -apple-system;display:flex;align-items:center;justify-content:center;height:100vh;margin:0'>Starting…</body>", baseURL: nil)
        let started = Date()
        Timer.scheduledTimer(withTimeInterval: 0.3, repeats: true) { [weak self] timer in
            guard let self = self else { return timer.invalidate() }
            if let r = readRunning() {
                timer.invalidate()
                self.loaded = true
                self.web.load(URLRequest(url: URL(string: "http://127.0.0.1:\(r.port)/?t=\(r.token)")!))
            } else if Date().timeIntervalSince(started) > 45 {
                timer.invalidate()
                self.web.loadHTMLString("<style>:root{color-scheme:light dark}@media(prefers-color-scheme:dark){body{background:#0d0f13}}@media(prefers-color-scheme:light){body{background:#f4f6f9}}</style><body style='color:#d33;font:14px -apple-system;padding:48px'>The backend did not start. See ~/Library/Logs/x28-flasher.log</body>", baseURL: nil)
            }
        }
        Timer.scheduledTimer(withTimeInterval: 2, repeats: true) { [weak self] _ in
            guard let self = self, self.loaded else { return }
            if let b = self.backend, !b.isRunning { NSApp.terminate(nil) }          // the page's Quit button, or a crash
            if self.backend == nil, readRunning() == nil { NSApp.terminate(nil) }    // attached to a server that has gone
        }
    }

    func startBackend() {
        let exe = Bundle.main.executableURL!.deletingLastPathComponent().appendingPathComponent("x28-flasher")
        let p = Process()
        p.executableURL = exe
        p.environment = ProcessInfo.processInfo.environment.merging(["X28_NO_BROWSER": "1"]) { $1 }
        let log = home.appendingPathComponent("Library/Logs/x28-flasher.log")
        FileManager.default.createFile(atPath: log.path, contents: nil)
        if let h = try? FileHandle(forWritingTo: log) { p.standardOutput = h; p.standardError = h }
        do { try p.run(); backend = p } catch { NSLog("could not start backend: \(error)") }
    }

    /// True while the backend runs a job (a backup, a flash): quitting then needs a confirmation.
    func jobRunning() -> Bool {
        guard let r = readRunning(), let url = URL(string: "http://127.0.0.1:\(r.port)/api/state") else { return false }
        var req = URLRequest(url: url, timeoutInterval: 2)
        req.setValue("x28=\(r.token)", forHTTPHeaderField: "Cookie")
        var busy = false
        let done = DispatchSemaphore(value: 0)
        URLSession.shared.dataTask(with: req) { data, _, _ in
            if let data = data, let json = try? JSONSerialization.jsonObject(with: data) as? [String: Any], let job = json["job"] as? [String: Any] {
                busy = (job["running"] as? Bool) ?? false
            }
            done.signal()
        }.resume()
        _ = done.wait(timeout: .now() + 3)
        return busy
    }

    func applicationShouldTerminate(_ sender: NSApplication) -> NSApplication.TerminateReply {
        if jobRunning() {
            let a = NSAlert()
            a.messageText = "A job is still running"
            a.informativeText = "Quitting now stops it. A write that is cut off cannot be undone; a backup can be resumed."
            a.addButton(withTitle: "Keep running")
            a.addButton(withTitle: "Quit anyway")
            if a.runModal() == .alertFirstButtonReturn { return .terminateCancel }
        }
        return .terminateNow
    }

    func applicationWillTerminate(_ note: Notification) {
        if let b = backend, b.isRunning {
            b.terminate()
            b.waitUntilExit()
            try? FileManager.default.removeItem(at: runFile)
        }
    }

    func applicationShouldTerminateAfterLastWindowClosed(_ app: NSApplication) -> Bool { true }

    // The page uses alert(); WKWebView shows nothing unless the host does.
    func webView(_ w: WKWebView, runJavaScriptAlertPanelWithMessage message: String, initiatedByFrame f: WKFrameInfo, completionHandler: @escaping () -> Void) {
        let a = NSAlert(); a.messageText = message; a.runModal(); completionHandler()
    }

    func webView(_ w: WKWebView, runJavaScriptConfirmPanelWithMessage message: String, initiatedByFrame f: WKFrameInfo, completionHandler: @escaping (Bool) -> Void) {
        let a = NSAlert(); a.messageText = message; a.addButton(withTitle: "OK"); a.addButton(withTitle: "Cancel")
        completionHandler(a.runModal() == .alertFirstButtonReturn)
    }

    func buildMenu() {
        let main = NSMenu()
        let appItem = NSMenuItem(); main.addItem(appItem)
        let appMenu = NSMenu(); appItem.submenu = appMenu
        appMenu.addItem(withTitle: "Quit X28 Flasher", action: #selector(NSApplication.terminate(_:)), keyEquivalent: "q")
        let editItem = NSMenuItem(); main.addItem(editItem)
        let edit = NSMenu(title: "Edit"); editItem.submenu = edit
        edit.addItem(withTitle: "Cut", action: #selector(NSText.cut(_:)), keyEquivalent: "x")
        edit.addItem(withTitle: "Copy", action: #selector(NSText.copy(_:)), keyEquivalent: "c")
        edit.addItem(withTitle: "Paste", action: #selector(NSText.paste(_:)), keyEquivalent: "v")
        edit.addItem(withTitle: "Select All", action: #selector(NSText.selectAll(_:)), keyEquivalent: "a")
        NSApp.mainMenu = main
    }
}

let app = NSApplication.shared
let delegate = AppDelegate()
app.delegate = delegate
app.setActivationPolicy(.regular)
app.run()
