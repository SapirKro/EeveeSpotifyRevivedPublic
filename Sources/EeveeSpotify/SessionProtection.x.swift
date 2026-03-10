import Orion
import Foundation

// MARK: - Session Logout Protection
// Hooks all logout-related methods to prevent Spotify from logging out
// when it detects the account isn't actually premium.
// Also intercepts Ably WebSocket messages to block server-side revocation events.
// Additionally blocks network endpoints that trigger session invalidation.
// Extends OAuth token expiry to prevent internal reauth triggers.

struct SessionLogoutHookGroup: HookGroup { }

// Ably action name mapping for readable logs
private let ablyActionNames: [Int: String] = [
    0: "heartbeat", 1: "ack", 2: "nack", 3: "connect", 4: "connected",
    5: "disconnect", 6: "disconnected", 7: "close", 8: "closed", 9: "error",
    10: "attach", 11: "attached", 12: "detach", 13: "detached",
    14: "presence", 15: "message", 16: "sync", 17: "auth"
]

// MARK: - SPTAuthSessionImplementation — Core Session Hooks

class SPTAuthSessionHook: ClassHook<NSObject> {
    typealias Group = SessionLogoutHookGroup
    static let targetName = "SPTAuthSessionImplementation"

    // orion:new
    static var allowLogout = false

    func logout() {
        let elapsed = Int(Date().timeIntervalSince(tweakInitTime))
        if SPTAuthSessionHook.allowLogout {
            writeDebugLog("[AUTH] Allowed logout() at \(elapsed)s (user-initiated)")
            orig.logout()
        } else {
            writeDebugLog("[AUTH] Blocked logout() at \(elapsed)s")
        }
    }

    func logoutWithReason(_ reason: AnyObject) {
        let elapsed = Int(Date().timeIntervalSince(tweakInitTime))
        if SPTAuthSessionHook.allowLogout {
            writeDebugLog("[AUTH] Allowed logoutWithReason at \(elapsed)s: \(reason)")
            orig.logoutWithReason(reason)
        } else {
            writeDebugLog("[AUTH] Blocked logoutWithReason at \(elapsed)s: \(reason)")
        }
    }

    func callSessionDidLogoutOnDelegateWithReason(_ reason: AnyObject) {
        let elapsed = Int(Date().timeIntervalSince(tweakInitTime))
        if SPTAuthSessionHook.allowLogout {
            writeDebugLog("[AUTH] Allowed callSessionDidLogoutOnDelegate at \(elapsed)s: \(reason)")
            orig.callSessionDidLogoutOnDelegateWithReason(reason)
        } else {
            writeDebugLog("[AUTH] Blocked callSessionDidLogoutOnDelegate at \(elapsed)s: \(reason)")
        }
    }

    func logWillLogoutEventWithLogoutReason(_ reason: AnyObject) {
        let elapsed = Int(Date().timeIntervalSince(tweakInitTime))
        if SPTAuthSessionHook.allowLogout {
            writeDebugLog("[AUTH] Allowed logWillLogoutEvent at \(elapsed)s: \(reason)")
            orig.logWillLogoutEventWithLogoutReason(reason)
        } else {
            writeDebugLog("[AUTH] Blocked logWillLogoutEvent at \(elapsed)s: \(reason)")
        }
    }

    func destroy() {
        let elapsed = Int(Date().timeIntervalSince(tweakInitTime))
        if SPTAuthSessionHook.allowLogout {
            writeDebugLog("[AUTH] Allowed session destroy at \(elapsed)s")
            orig.destroy()
        } else {
            writeDebugLog("[AUTH] Blocked session destroy at \(elapsed)s")
        }
    }

    func productStateUpdated(_ state: AnyObject) {
        let elapsed = Int(Date().timeIntervalSince(tweakInitTime))
        writeDebugLog("[AUTH] productStateUpdated at \(elapsed)s — \(state)")
        orig.productStateUpdated(state)
    }

    func tryReconnect(_ arg1: AnyObject, toAP arg2: AnyObject) {
        let elapsed = Int(Date().timeIntervalSince(tweakInitTime))
        writeDebugLog("[AUTH] tryReconnect at \(elapsed)s — AP: \(arg2)")
        orig.tryReconnect(arg1, toAP: arg2)
    }
}

// MARK: - SessionServiceImpl (Connectivity_SessionImpl module)

class SessionServiceImplHook: ClassHook<NSObject> {
    typealias Group = SessionLogoutHookGroup
    static let targetName = "_TtC24Connectivity_SessionImpl18SessionServiceImpl"

    func automatedLogoutThenLogin() {
        let elapsed = Int(Date().timeIntervalSince(tweakInitTime))
        writeDebugLog("[SESSION] Blocked automatedLogoutThenLogin at \(elapsed)s")
    }

    func userInitiatedLogout() {
        let elapsed = Int(Date().timeIntervalSince(tweakInitTime))
        let isMain = Thread.isMainThread
        if isMain {
            writeDebugLog("[SESSION] Allowed userInitiatedLogout at \(elapsed)s (main thread — real user tap)")
            SPTAuthSessionHook.allowLogout = true
            orig.userInitiatedLogout()
            DispatchQueue.main.asyncAfter(deadline: .now() + 5) {
                SPTAuthSessionHook.allowLogout = false
                writeDebugLog("[SESSION] allowLogout reset to false")
            }
        } else {
            writeDebugLog("[SESSION] Blocked automated userInitiatedLogout at \(elapsed)s (thread: \(Thread.current.name ?? "unnamed"), isMain: \(isMain))")
        }
    }

    func sessionDidLogout(_ session: AnyObject, withReason reason: AnyObject) {
        let elapsed = Int(Date().timeIntervalSince(tweakInitTime))
        if SPTAuthSessionHook.allowLogout {
            writeDebugLog("[SESSION] Allowed sessionDidLogout at \(elapsed)s: \(reason)")
            orig.sessionDidLogout(session, withReason: reason)
        } else {
            writeDebugLog("[SESSION] Blocked sessionDidLogout at \(elapsed)s: \(reason)")
        }
    }
}

// MARK: - SPTAuthLegacyLoginControllerImplementation

class LegacyLoginControllerHook: ClassHook<NSObject> {
    typealias Group = SessionLogoutHookGroup
    static let targetName = "SPTAuthLegacyLoginControllerImplementation"

    func sessionDidLogout(_ session: AnyObject, withReason reason: AnyObject) {
        let elapsed = Int(Date().timeIntervalSince(tweakInitTime))
        if SPTAuthSessionHook.allowLogout {
            writeDebugLog("[LEGACY] Allowed sessionDidLogout at \(elapsed)s: \(reason)")
            orig.sessionDidLogout(session, withReason: reason)
        } else {
            writeDebugLog("[LEGACY] Blocked sessionDidLogout at \(elapsed)s: \(reason)")
        }
    }

    func destroySession() {
        let elapsed = Int(Date().timeIntervalSince(tweakInitTime))
        if SPTAuthSessionHook.allowLogout {
            writeDebugLog("[LEGACY] Allowed destroySession at \(elapsed)s")
            orig.destroySession()
        } else {
            writeDebugLog("[LEGACY] Blocked destroySession at \(elapsed)s")
        }
    }

    func forgetStoredCredentials() {
        let elapsed = Int(Date().timeIntervalSince(tweakInitTime))
        if SPTAuthSessionHook.allowLogout {
            writeDebugLog("[LEGACY] Allowed forgetStoredCredentials at \(elapsed)s")
            orig.forgetStoredCredentials()
        } else {
            writeDebugLog("[LEGACY] Blocked forgetStoredCredentials at \(elapsed)s")
        }
    }

    func invalidate() {
        let elapsed = Int(Date().timeIntervalSince(tweakInitTime))
        if SPTAuthSessionHook.allowLogout {
            writeDebugLog("[LEGACY] Allowed invalidate at \(elapsed)s")
            orig.invalidate()
        } else {
            writeDebugLog("[LEGACY] Blocked invalidate at \(elapsed)s")
        }
    }
}

// MARK: - OauthAccessTokenBridge — Extend token expiry

class OauthAccessTokenBridgeHook: ClassHook<NSObject> {
    typealias Group = SessionLogoutHookGroup
    static let targetName = "_TtC24Connectivity_SessionImplP33_831B98CC28223E431E21CD27ADD20AF222OauthAccessTokenBridge"

    func expiresAt() -> Any {
        let origValue = orig.expiresAt()
        let farFuture = Date(timeIntervalSinceNow: 365 * 24 * 60 * 60)
        let elapsed = Int(Date().timeIntervalSince(tweakInitTime))
        if let origDate = origValue as? Date {
            let remaining = Int(origDate.timeIntervalSinceNow)
            writeDebugLog("[TOKEN] expiresAt getter at \(elapsed)s — original expiry in \(remaining)s, returning +1yr")
        } else {
            writeDebugLog("[TOKEN] expiresAt getter at \(elapsed)s — original was \(type(of: origValue)), returning +1yr")
        }
        return farFuture
    }

    func setExpiresAt(_ date: Any) {
        let elapsed = Int(Date().timeIntervalSince(tweakInitTime))
        if let d = date as? Date {
            let remaining = Int(d.timeIntervalSinceNow)
            writeDebugLog("[TOKEN] setExpiresAt at \(elapsed)s — attempted expiry in \(remaining)s, overriding to +1yr")
        } else {
            writeDebugLog("[TOKEN] setExpiresAt at \(elapsed)s — attempted \(type(of: date)), overriding to +1yr")
        }
        let farFuture = Date(timeIntervalSinceNow: 365 * 24 * 60 * 60)
        orig.setExpiresAt(farFuture)
    }

    func `init`() -> NSObject? {
        let result = orig.`init`()
        writeDebugLog("[TOKEN] OauthAccessTokenBridge init — extending expiry ivar + starting extender timer")
        extendExpiryIvar()
        startExpiryExtender()
        return result
    }

    // orion:new
    func extendExpiryIvar() {
        let bridgeClass: AnyClass = type(of: target)
        if let ivar = class_getInstanceVariable(bridgeClass, "expiresAt") {
            let farFuture = Date(timeIntervalSinceNow: 365 * 24 * 60 * 60)
            object_setIvar(target, ivar, farFuture)
        } else {
            writeDebugLog("[TOKEN] Could not find expiresAt ivar on \(bridgeClass)")
        }
    }

    // orion:new
    func startExpiryExtender() {
        let weak = target
        DispatchQueue.global(qos: .utility).async {
            while true {
                Thread.sleep(forTimeInterval: 60)
                guard let obj = weak as? NSObject else {
                    writeDebugLog("[TOKEN] Expiry extender: token bridge object deallocated")
                    break
                }
                let cls: AnyClass = type(of: obj)
                if let ivar = class_getInstanceVariable(cls, "expiresAt") {
                    let farFuture = Date(timeIntervalSinceNow: 365 * 24 * 60 * 60)
                    object_setIvar(obj, ivar, farFuture)
                }
            }
        }
    }
}



// NOTE: ColdStartupTimeKeeperImplementation is a pure Swift class (not NSObject).
// Cannot hook it with Orion — crashes with targetHasIncompatibleType.
// NOTE: executeBlockRunner on SPTAsyncNativeTimerManagerThreadImpl is too broad —
// blocking it kills ALL timers including playback advancement.

// MARK: - Ably WebSocket Transport Hooks
// Intercepts Ably real-time messages to block server-side logout/revocation events

// Blocked Ably protocol actions:
// 5=disconnect, 6=disconnected, 7=close, 8=closed, 9=error, 12=detach, 13=detached, 17=auth
private let blockedAblyActions: Set<Int> = [5, 6, 7, 8, 9, 12, 13, 17]

private func extractAblyAction(_ text: String) -> Int? {
    guard let range = text.range(of: "\"action\":") else { return nil }
    let afterAction = text[range.upperBound...]
    let digits = afterAction.prefix(while: { $0.isNumber })
    return Int(digits)
}

class ARTWebSocketTransportHook: ClassHook<NSObject> {
    typealias Group = SessionLogoutHookGroup
    static let targetName = "ARTWebSocketTransport"

    func webSocket(_ ws: AnyObject, didReceiveMessage message: AnyObject) {
        if let msgString = message as? String {
            if let action = extractAblyAction(msgString) {
                let actionName = ablyActionNames[action] ?? "unknown"
                if blockedAblyActions.contains(action) {
                    let elapsed = Int(Date().timeIntervalSince(tweakInitTime))
                    writeDebugLog("[ABLY] Blocked action \(action) (\(actionName)) at \(elapsed)s")
                    return
                }
            }
        }
        orig.webSocket(ws, didReceiveMessage: message)
    }

    func webSocket(_ ws: AnyObject, didFailWithError error: AnyObject) {
        let elapsed = Int(Date().timeIntervalSince(tweakInitTime))
        writeDebugLog("[ABLY] Blocked WebSocket didFailWithError at \(elapsed)s: \(error)")
    }

    func webSocketDidOpen(_ ws: AnyObject) {
        let elapsed = Int(Date().timeIntervalSince(tweakInitTime))
        writeDebugLog("[ABLY] WebSocket opened at \(elapsed)s")
        orig.webSocketDidOpen(ws)
    }
}

// MARK: - Ably SRWebSocket Frame Hook

class ARTSRWebSocketHook: ClassHook<NSObject> {
    typealias Group = SessionLogoutHookGroup
    static let targetName = "ARTSRWebSocket"

    func _handleFrameWithData(_ data: NSData, opCode code: Int) {
        if code == 1,
           let text = String(data: data as Data, encoding: .utf8) {
            if let action = extractAblyAction(text) {
                let actionName = ablyActionNames[action] ?? "unknown"
                if blockedAblyActions.contains(action) {
                    let elapsed = Int(Date().timeIntervalSince(tweakInitTime))
                    writeDebugLog("[ABLY-SR] Blocked frame action \(action) (\(actionName)) at \(elapsed)s")
                    return
                }
            }
        }
        orig._handleFrameWithData(data, opCode: code)
    }

    func close() {
        let elapsed = Int(Date().timeIntervalSince(tweakInitTime))
        writeDebugLog("[ABLY-SR] Blocked SRWebSocket close at \(elapsed)s")
    }

    func closeWithCode(_ code: Int, reason: AnyObject?) {
        let elapsed = Int(Date().timeIntervalSince(tweakInitTime))
        writeDebugLog("[ABLY-SR] Blocked SRWebSocket closeWithCode \(code) at \(elapsed)s reason: \(reason ?? "nil" as AnyObject)")
    }
}

// MARK: - Global URLSessionTask hook to catch auth traffic bypassing SPTDataLoaderService

// Track auth-related URL patterns we've already logged to avoid spam
private var loggedAuthURLPatterns = Set<String>()
private let authURLLogLock = NSLock()

class URLSessionTaskResumeHook: ClassHook<NSObject> {
    typealias Group = SessionLogoutHookGroup
    static let targetName = "NSURLSessionTask"

    func resume() {
        if let task = target as? URLSessionTask,
           let url = task.currentRequest?.url ?? task.originalRequest?.url,
           let host = url.host?.lowercased() {

            let elapsed = Date().timeIntervalSince(tweakInitTime)
            let elapsedInt = Int(elapsed)
            let path = url.path

            // Log ALL auth-related requests (not just blocked ones)
            let isAuthRelated = host.contains("login5") ||
                host.contains("apresolve") ||
                (host.contains("googleapis.com") && path.contains("/token")) ||
                path.contains("bootstrap/v1/bootstrap") ||
                path.contains("DeleteToken") ||
                path.contains("signup/public") ||
                path.contains("pses/screenconfig") ||
                path.contains("logout") ||
                path.contains("sign-out") ||
                path.contains("session/purge") ||
                path.contains("token/revoke") ||
                path.contains("auth/expire") ||
                path.contains("product-state") ||
                path.contains("melody") ||
                path.contains("auth/v1")

            if isAuthRelated {
                let method = task.currentRequest?.httpMethod ?? "?"
                writeDebugLog("[NET] Auth request: \(method) \(host)\(path) at \(elapsedInt)s")
            }

            // After initial startup (30s), block login5 re-auth requests.
            if elapsed > 30 {
                if host.contains("login5") {
                    writeDebugLog("[NET] Blocked login5 re-auth at \(elapsedInt)s: \(host)\(path)")
                    return
                }
                if host.contains("googleapis.com") && path.contains("/token") {
                    writeDebugLog("[NET] Blocked Google OAuth refresh at \(elapsedInt)s")
                    return
                }
            }

            // Block outgoing DeleteToken/signup requests at network level
            if host.contains("spotify") || host.contains("spclient") {
                if path.contains("DeleteToken") {
                    writeDebugLog("[NET] Blocked DeleteToken at \(elapsedInt)s")
                    return
                }
                if path.contains("signup/public") {
                    writeDebugLog("[NET] Blocked signup/public at \(elapsedInt)s")
                    return
                }
                if path.contains("pses/screenconfig") {
                    writeDebugLog("[NET] Blocked pses/screenconfig at \(elapsedInt)s")
                    return
                }
                if elapsed > 30 && path.contains("bootstrap/v1/bootstrap") {
                    writeDebugLog("[NET] Blocked bootstrap re-fetch at \(elapsedInt)s")
                    return
                }
                if elapsed > 30 && host.contains("apresolve") {
                    writeDebugLog("[NET] Blocked apresolve at \(elapsedInt)s")
                    return
                }
            }
        }
        orig.resume()
    }
}


