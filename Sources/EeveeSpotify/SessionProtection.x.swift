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
    // Specifies the Objective-C class name to hook: SPTAuthSessionImplementation
    static let targetName = "SPTAuthSessionImplementation"

    // orion:new
    // Global flag to control if a logout should strictly be allowed (e.g. user tapped "Log out")
    static var allowLogout = false

    func logout() {
        // Calculate time elapsed since app start for logging context
        let elapsed = Int(Date().timeIntervalSince(tweakInitTime))
        
        // Check if the user explicitly initiated this logout via our flag
        if SPTAuthSessionHook.allowLogout {
            writeDebugLog("[AUTH] Allowed logout() at \(elapsed)s")
            // Call the original method to actually log out
            orig.logout()
        } else {
            // Otherwise, ignore the logout command from the app/server
            writeDebugLog("[AUTH] Blocked logout() at \(elapsed)s")
        }
    }

    func logoutWithReason(_ reason: AnyObject) {
        let elapsed = Int(Date().timeIntervalSince(tweakInitTime))
        
        // Check if we should allow this specific logout attempt
        if SPTAuthSessionHook.allowLogout {
            writeDebugLog("[AUTH] Allowed logoutWithReason at \(elapsed)s: \(reason)")
            orig.logoutWithReason(reason)
        } else {
            // Block the logout and log the reason provided by Spotify
            writeDebugLog("[AUTH] Blocked logoutWithReason at \(elapsed)s: \(reason)")
        }
    }

    func callSessionDidLogoutOnDelegateWithReason(_ reason: AnyObject) {
        let elapsed = Int(Date().timeIntervalSince(tweakInitTime))
        
        // Prevent the delegate (UI/App logic) from being notified that a logout happened
        if SPTAuthSessionHook.allowLogout {
            orig.callSessionDidLogoutOnDelegateWithReason(reason)
        } else {
            writeDebugLog("[AUTH] Blocked callSessionDidLogoutOnDelegate at \(elapsed)s: \(reason)")
        }
    }

    func logWillLogoutEventWithLogoutReason(_ reason: AnyObject) {
        let elapsed = Int(Date().timeIntervalSince(tweakInitTime))
        
        // Prevent internal analytics/logging events regarding the forced logout
        if SPTAuthSessionHook.allowLogout {
            orig.logWillLogoutEventWithLogoutReason(reason)
        } else {
            writeDebugLog("[AUTH] Blocked logWillLogoutEvent at \(elapsed)s: \(reason)")
        }
    }

    func destroy() {
        let elapsed = Int(Date().timeIntervalSince(tweakInitTime))
        
        // Crucial: 'destroy' tears down the underlying C++ session object.
        // We block this to keep the session valid in memory.
        if SPTAuthSessionHook.allowLogout {
            orig.destroy()
        } else {
            // Capture a stack trace to see what triggered the destroy
            let trace = Thread.callStackSymbols.prefix(15).joined(separator: "\n")
            writeDebugLog("[AUTH] Blocked session destroy at \(elapsed)s\n[TRACE] \(trace)")
        }
    }

    func productStateUpdated(_ state: AnyObject) {
        let elapsed = Int(Date().timeIntervalSince(tweakInitTime))
        // Spy on product state updates (e.g. Free vs Premium status changes) for debugging
        writeDebugLog("[AUTH] productStateUpdated at \(elapsed)s -- \(state)")
        // Pass through to original implementation so the app updates its UI/state
        orig.productStateUpdated(state)
    }

    func tryReconnect(_ arg1: AnyObject, toAP arg2: AnyObject) {
        let elapsed = Int(Date().timeIntervalSince(tweakInitTime))
        // Spy on reconnection attempts to access points
        writeDebugLog("[AUTH] tryReconnect at \(elapsed)s -- AP: \(arg2)")
        // Pass through to allow normal reconnection behavior
        orig.tryReconnect(arg1, toAP: arg2)
    }
}

// MARK: - SessionServiceImpl (Connectivity_SessionImpl module)

class SessionServiceImplHook: ClassHook<NSObject> {
    typealias Group = SessionLogoutHookGroup
    // Target the Swift-based session service implementation
    static let targetName = "_TtC24Connectivity_SessionImpl18SessionServiceImpl"

    func automatedLogoutThenLogin() {
        let elapsed = Int(Date().timeIntervalSince(tweakInitTime))
        // Completely block this method. It is often used by the app to force a session refresh
        // or re-login, which can trigger account validation and subsequent downgrade to free.
        writeDebugLog("[SESSION] Blocked automatedLogoutThenLogin at \(elapsed)s")
    }

    func userInitiatedLogout() {
        let elapsed = Int(Date().timeIntervalSince(tweakInitTime))
        
        // Check if the call is coming from the Main Thread (UI interaction).
        // Real user clicks happen on the main thread.
        if Thread.isMainThread {
            writeDebugLog("[SESSION] Allowed userInitiatedLogout at \(elapsed)s (main thread)")
            // Temporarily allow logout so the user can sign out via Settings.
            SPTAuthSessionHook.allowLogout = true
            // Execute the original logout logic
            orig.userInitiatedLogout()
            // Reset the flag after 5 seconds to re-enable protection.
            DispatchQueue.main.asyncAfter(deadline: .now() + 5) {
                SPTAuthSessionHook.allowLogout = false
            }
        } else {
            // Block calls from background threads, as these are likely internal
            // app mechanisms trying to force a logout, not the user.
            writeDebugLog("[SESSION] Blocked automated userInitiatedLogout at \(elapsed)s (bg thread)")
        }
    }

    func sessionDidLogout(_ session: AnyObject, withReason reason: AnyObject) {
        let elapsed = Int(Date().timeIntervalSince(tweakInitTime))
        
        // Prevent the session service from notifying listeners about a logout
        // unless it was explicitly allowed (via the userInitiatedLogout flow).
        if SPTAuthSessionHook.allowLogout {
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
        // Check if logout is explicitly allowed by user action
        if SPTAuthSessionHook.allowLogout {
            orig.sessionDidLogout(session, withReason: reason)
        } else {
            // Block the legacy logout notification to prevent UI updates
            writeDebugLog("[LEGACY] Blocked sessionDidLogout at \(elapsed)s: \(reason)")
        }
    }

    func destroySession() {
        let elapsed = Int(Date().timeIntervalSince(tweakInitTime))
        // destroySession wipes the C++ session object. We must prevent this to keep music playing.
        if SPTAuthSessionHook.allowLogout {
            orig.destroySession()
        } else {
            writeDebugLog("[LEGACY] Blocked destroySession at \(elapsed)s")
        }
    }

    func forgetStoredCredentials() {
        let elapsed = Int(Date().timeIntervalSince(tweakInitTime))
        // Prevent the app from deleting the saved login token from disk/keychain
        if SPTAuthSessionHook.allowLogout {
            orig.forgetStoredCredentials()
        } else {
            writeDebugLog("[LEGACY] Blocked forgetStoredCredentials at \(elapsed)s")
        }
    }

    func invalidate() {
        let elapsed = Int(Date().timeIntervalSince(tweakInitTime))
        // Prevent the controller from marking itself as invalid/logged out
        if SPTAuthSessionHook.allowLogout {
            orig.invalidate()
        } else {
            writeDebugLog("[LEGACY] Blocked invalidate at \(elapsed)s")
        }
    }
}

// MARK: - OauthAccessTokenBridge — Extend token expiry
// This private class inside Connectivity_SessionImpl controls the OAuth token's
// expiry time. By hooking expiresAt to return a far-future date, we prevent
// the internal timer from marking the token as expired.

class OauthAccessTokenBridgeHook: ClassHook<NSObject> {
    typealias Group = SessionLogoutHookGroup
    static let targetName = "_TtC24Connectivity_SessionImplP33_831B98CC28223E431E21CD27ADD20AF222OauthAccessTokenBridge"

    // Hook the GETTER
    func expiresAt() -> Any {
        // Return a date 1 year in the future so the app thinks the token is valid
        let farFuture = Date(timeIntervalSinceNow: 365 * 24 * 60 * 60)
        return farFuture
    }

    func setExpiresAt(_ date: Any) {
        // Force any attempt to set the expiry date to be 1 year in the future
        let farFuture = Date(timeIntervalSinceNow: 365 * 24 * 60 * 60)
        orig.setExpiresAt(farFuture)
    }

    // Hook init to directly modify the ivar using ObjC runtime
    // This catches cases where C++ sets the ivar without going through the ObjC setter
    func `init`() -> NSObject? {
        let result = orig.`init`()
        // Manually overwrite the instance variable immediately after creation
        extendExpiryIvar()
        // Also start a repeating timer to keep extending the ivar
        startExpiryExtender()
        return result
    }

    // orion:new
    func extendExpiryIvar() {
        // Get the class type
        let bridgeClass: AnyClass = type(of: target)
        // Look up the instance variable "expiresAt"
        if let ivar = class_getInstanceVariable(bridgeClass, "expiresAt") {
            // Create date 1 year in future
            let farFuture = Date(timeIntervalSinceNow: 365 * 24 * 60 * 60)
            // Write directly to memory, bypassing property setters
            object_setIvar(target, ivar, farFuture)
        }
    }

    // orion:new
    func startExpiryExtender() {
        // Keep a weak reference to avoid retain cycles
        let weak = target
        // Extend the ivar every 60 seconds
        DispatchQueue.global(qos: .utility).async {
            while true {
                // Wait 60 seconds
                Thread.sleep(forTimeInterval: 60)
                // Check if object still exists
                guard let obj = weak as? NSObject else { break }
                let cls: AnyClass = type(of: obj)
                // Overwrite the variable again
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

// Helper function to parse raw JSON strings from the WebSocket.
// - It searches for the string "action":.
// - It grabs the numbers immediately following it.
// - It returns the integer action code (e.g., 15 or 5).
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
            // Check if message contains an action code
            if let action = extractAblyAction(msgString) {
                let actionName = ablyActionNames[action] ?? "unknown"
                let elapsed = Int(Date().timeIntervalSince(tweakInitTime))
                // Check if this action is in our block list (e.g. disconnect/auth fail)
                if blockedAblyActions.contains(action) {
                    writeDebugLog("[ABLY] Blocked action \(action) (\(actionName)) at \(elapsed)s")
                    // Return early, swallowing the message so the app never sees it
                    return
                }
                // Log action-15 (message) payloads — these may carry logout signals
                if action == 15 {
                    let preview = String(msgString.prefix(300))
                    writeDebugLog("[ABLY] Message (action 15) at \(elapsed)s: \(preview)")
                }
            }
        }
        // Pass legitimate messages to original handler
        orig.webSocket(ws, didReceiveMessage: message)
    }

    func webSocket(_ ws: AnyObject, didFailWithError error: AnyObject) {
        let elapsed = Int(Date().timeIntervalSince(tweakInitTime))
        // Log WebSocket errors (often happens when we block auth packets)
        writeDebugLog("[ABLY] Blocked WebSocket didFailWithError at \(elapsed)s: \(error)")
    }
}

// MARK: - Ably SRWebSocket Frame Hook

class ARTSRWebSocketHook: ClassHook<NSObject> {
    typealias Group = SessionLogoutHookGroup
    static let targetName = "ARTSRWebSocket"

    func _handleFrameWithData(_ data: NSData, opCode code: Int) {
        // OpCode 1 is a text frame
        if code == 1,
           let text = String(data: data as Data, encoding: .utf8) {
            // Parse action from text
            if let action = extractAblyAction(text) {
                let actionName = ablyActionNames[action] ?? "unknown"
                let elapsed = Int(Date().timeIntervalSince(tweakInitTime))
                // Check block list
                if blockedAblyActions.contains(action) {
                    writeDebugLog("[ABLY-SR] Blocked frame action \(action) (\(actionName)) at \(elapsed)s")
                    // Drop the frame
                    return
                }
                // Log action-15 (message) payloads — these may carry logout signals
                if action == 15 {
                    let preview = String(text.prefix(300))
                    writeDebugLog("[ABLY-SR] Message (action 15) at \(elapsed)s: \(preview)")
                }
            }
        }
        // Process allowed frames
        orig._handleFrameWithData(data, opCode: code)
    }
}

// MARK: - Global URLSessionTask hook to catch auth traffic bypassing SPTDataLoaderService

class URLSessionTaskResumeHook: ClassHook<NSObject> {
    typealias Group = SessionLogoutHookGroup
    static let targetName = "NSURLSessionTask"

    func resume() {
        // Check if the target is a URLSessionTask and get its URL
        if let task = target as? URLSessionTask,
           let url = task.currentRequest?.url ?? task.originalRequest?.url,
           let host = url.host?.lowercased() {

            let elapsed = Date().timeIntervalSince(tweakInitTime)
            let elapsedInt = Int(elapsed)
            let path = url.path

            // Log auth-related requests for diagnostics
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

            // NOTE: Do NOT block login5 or googleapis.com/token.
            // login5 re-auths every ~3 min; blocking it causes a crash/panic loop.
            // Logout protection comes from blocking session destroy, DeleteToken, etc. below.

            // Block outgoing DeleteToken/signup requests at network level
            // Only block after initial startup (30s) to allow fresh login/signup
            if host.contains("spotify") || host.contains("spclient") {
                // DeleteToken: The app trying to invalidate its own session
                if elapsed > 30 && path.contains("DeleteToken") {
                    writeDebugLog("[NET] Cancelled DeleteToken at \(elapsedInt)s")
                    task.cancel() // Abort the network request
                    return
                }
                // signup/public: Often called when the app thinks it needs to register a new user
                if elapsed > 30 && path.contains("signup/public") {
                    writeDebugLog("[NET] Cancelled signup/public at \(elapsedInt)s")
                    task.cancel()
                    return
                }
                // screenconfig: UI configuration that might force a "Free" screen
                if elapsed > 30 && path.contains("pses/screenconfig") {
                    writeDebugLog("[NET] Cancelled pses/screenconfig at \(elapsedInt)s")
                    task.cancel()
                    return
                }
                // bootstrap: The initial config fetch. Blocking re-fetches prevents config updates (like "downgrade to free")
                if elapsed > 30 && path.contains("bootstrap/v1/bootstrap") {
                    writeDebugLog("[NET] Cancelled bootstrap re-fetch at \(elapsedInt)s")
                    task.cancel()
                    return
                }
                // apresolve: Resolves access point URLs. Blocking helps prevent connecting to new auth servers.
                if elapsed > 30 && host.contains("apresolve") {
                    writeDebugLog("[NET] Cancelled apresolve at \(elapsedInt)s")
                    task.cancel()
                    return
                }
            }
        }
        // Proceed with normal network request if not blocked
        orig.resume()
    }
}
