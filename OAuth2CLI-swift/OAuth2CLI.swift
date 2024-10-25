//
//  main.swift
//  OAuth2CLI-swift
//
//  Created by Hanwen Guo on 10/23/24.
//

import Foundation
import Security
import CryptoKit

import ArgumentParser

struct RegistrationConfig {
    let authorizeEndpoint: String
    let devicecodeEndpoint: String
    let tokenEndpoint: String
    let redirectUri: String
    let imapEndpoint: String
    let popEndpoint: String
    let smtpEndpoint: String
    let saslMethod: String
    let scope: String
    let clientId: String
    let clientSecret: String? // only for Google
    let tenant: String? // only for Microsoft
}

// The clientId and clientSecret are taken from Thunderbird,
// you'd better register your own application.
let registrations: [String: RegistrationConfig] = [
    "google": RegistrationConfig(
        authorizeEndpoint: "https://accounts.google.com/o/oauth2/auth",
        devicecodeEndpoint: "https://oauth2.googleapis.com/device/code",
        tokenEndpoint: "https://www.googleapis.com/oauth2/v3/token",
        redirectUri: "urn:ietf:wg:oauth:2.0:oob",
        imapEndpoint: "imap.gmail.com",
        popEndpoint: "pop.gmail.com",
        smtpEndpoint: "smtp.gmail.com",
        saslMethod: "OAUTHBEARER",
        scope: "https://mail.google.com/",
        clientId: "406964657835-aq8lmia8j95dhl1a2bvharmfk3t1hgqj.apps.googleusercontent.com",
        clientSecret: "kSmqreRr0qwBWJgbf5Y-PjSU",
        tenant: nil
    ),
    
    "microsoft": RegistrationConfig(
        authorizeEndpoint: "https://login.microsoftonline.com/common/oauth2/v2.0/authorize",
        devicecodeEndpoint: "https://login.microsoftonline.com/common/oauth2/v2.0/devicecode",
        tokenEndpoint: "https://login.microsoftonline.com/common/oauth2/v2.0/token",
        redirectUri: "https://login.microsoftonline.com/common/oauth2/nativeclient",
        imapEndpoint: "outlook.office365.com",
        popEndpoint: "outlook.office365.com",
        smtpEndpoint: "smtp.office365.com",
        saslMethod: "XOAUTH2",
        scope: "offline_access https://outlook.office.com/IMAP.AccessAsUser.All " +
               "https://outlook.office.com/POP.AccessAsUser.All " +
               "https://outlook.office.com/SMTP.Send",
        clientId: "9e5f94bc-e8a4-4e73-b8be-63364c29d753",
        clientSecret: nil,
        tenant: "common"
    )
]


// Define a struct for token data
struct TokenData: Codable {
    var registration: String
    var authflow: String
    var email: String
    var accessToken: String
    var accessTokenExpiration: String
    var refreshToken: String
    
    enum CodingKeys: String, CodingKey {
        case registration = "registration"
        case authflow = "authflow"
        case email = "email"
        case accessToken = "access_token"
        case accessTokenExpiration = "access_token_expiration"
        case refreshToken = "refresh_token"
    }
    
    static func == (lhs: TokenData, rhs: TokenData) -> Bool {
        lhs.registration == rhs.registration &&
        lhs.authflow == rhs.authflow &&
        lhs.email == rhs.email &&
        lhs.accessToken == rhs.accessToken &&
        lhs.accessTokenExpiration == rhs.accessTokenExpiration &&
        lhs.refreshToken == rhs.refreshToken
    }
    
    // Empty token data
    static var empty: TokenData {
        TokenData(
            registration: "",
            authflow: "",
            email: "",
            accessToken: "",
            accessTokenExpiration: "",
            refreshToken: ""
        )
    }
    
    var isAccessTokenValid: Bool {
        if !accessTokenExpiration.isEmpty {
            guard let expirationDate = ISO8601DateFormatter().date(from: accessTokenExpiration)
            else { return false }
            return Date() < expirationDate
        } else {
            return false
        }
    }
    
    mutating func updateTokens(from response: TokenResponse) throws {
        self.accessToken = response.accessToken
        
        let expirationDate = Date().addingTimeInterval(TimeInterval(response.expiresIn))
        self.accessTokenExpiration = ISO8601DateFormatter().string(from: expirationDate)
        
        if let refreshToken = response.refreshToken {
            self.refreshToken = refreshToken
        }
    }
}

// Response model for token endpoint
struct TokenResponse: Decodable {
    let accessToken: String
    let expiresIn: Int
    let refreshToken: String?
    let error: String?
    let errorDescription: String?
    
    enum CodingKeys: String, CodingKey {
        case accessToken = "access_token"
        case expiresIn = "expires_in"
        case refreshToken = "refresh_token"
        case error = "error"
        case errorDescription = "error_description"
    }
}

final class KeychainManager: Sendable {
    static let shared = KeychainManager()
    private let service = "cc.froup.oauth2cli-swift"
    
    private init() {}
    
    func readToken(forEmail email: String) -> TokenData? {
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: email,
            kSecReturnData as String: true
        ]
        
        var result: AnyObject?
        let status = SecItemCopyMatching(query as CFDictionary, &result)
        
        guard status == errSecSuccess,
              let data = result as? Data,
              let token = try? JSONDecoder().decode(TokenData.self, from: data) else {
            return nil
        }
        
        return token
    }
        
    func saveOrUpdateToken(_ token: TokenData) throws {
        let tokenData = try JSONEncoder().encode(token)
        
        // Query to check if a token exists for this email
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: token.email
        ]
        
        // Attributes to update or add
        let attributes: [String: Any] = [
            kSecValueData as String: tokenData,
            kSecAttrAccount as String: token.email,
            kSecAttrService as String: service
        ]
        
        // Try to update first
        var status = SecItemUpdate(query as CFDictionary, attributes as CFDictionary)
        
        if status == errSecItemNotFound {
            // Item doesn't exist, add it
            let addQuery = attributes.merging([
                kSecClass as String: kSecClassGenericPassword
            ]) { (_, new) in new }
            
            status = SecItemAdd(addQuery as CFDictionary, nil)
        }
        
        guard status == errSecSuccess else {
            throw KeychainError.unableToSave(status: status)
        }
    }
    
    func deleteToken(forEmail email: String) throws {
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: email
        ]
        
        let status = SecItemDelete(query as CFDictionary)
        guard status == errSecSuccess || status == errSecItemNotFound else {
            throw KeychainError.unableToDelete(status: status)
        }
    }
}

// Enhanced error enum
enum KeychainError: Error {
    case unableToSave(status: OSStatus)
    case unableToRead(status: OSStatus)
    case unableToDelete(status: OSStatus)
    
    var localizedDescription: String {
        switch self {
        case .unableToSave(let status):
            return "Failed to save to Keychain. Status: \(status)"
        case .unableToRead(let status):
            return "Failed to read from Keychain. Status: \(status)"
        case .unableToDelete(let status):
            return "Failed to delete from Keychain. Status: \(status)"
        }
    }
}

// Define the main command structure
@main
struct OAuth2CLI: AsyncParsableCommand {
    static let configuration = CommandConfiguration(
        commandName: "oauth-token",
        abstract: "Obtains and prints a valid OAuth2 access token",
        discussion: """
            This script obtains and prints a valid OAuth2 access token. State is maintained in 
            Apple Keychain. Run with "--verbose --authorize" to get started or whenever all tokens 
            have expired, optionally with "--authflow" to override the default authorization
            flow. To truly start over from scratch, first delete token in the Keychain.
            """
    )
    
    // Command-line arguments
    @Flag(name: .shortAndLong, help: "Increase verbosity")
    var verbose = false
    
    @Flag(name: .shortAndLong, help: "Enable debug output")
    var debug = false
    
    @Flag(name: .shortAndLong, help: "Manually authorize new tokens")
    var authorize = false
    
    @Option(help: "authcode | localhostauthcode | devicecode")
    var authflow: String?
    
    @Flag(name: .shortAndLong, help: "Test IMAP/POP/SMTP endpoints")
    var test = false
    
    @Argument(help: "email account")
    var email: String
    
    mutating func run() async throws {
        let debug = debug

        // Try to read existing token data
        var token = KeychainManager.shared.readToken(forEmail: email) ?? TokenData.empty
        
        if debug {
            let data = try JSONEncoder().encode(token)
            print("Obtained from Keychain:", String(data: data, encoding: .utf8)!)
        }
        
        // Handle new token authorization
        if token == TokenData.empty {
            if !authorize {
                print("Error: You must run with --authorize to create a new token.")
                OAuth2CLI.exit(withError: ExitCode(1))
            }
            
            // Show available registrations and get user input
            print("Available app and endpoint registrations:", registrations.keys.joined(separator: ", "))
            
            print("OAuth2 registration: ", terminator: "")
            guard let registration = readLine()?.lowercased(),
                  registrations[registration] != nil else {
                print("Error: Invalid registration selected")
                OAuth2CLI.exit(withError: ExitCode(1))
            }
            
            // Get or validate auth flow
            let flow: String
            if let authflow = self.authflow {
                guard ["authcode", "localhostauthcode", "devicecode"].contains(authflow.lowercased()) else {
                    print("Error: Invalid auth flow specified")
                    OAuth2CLI.exit(withError: ExitCode(1))
                }
                flow = authflow.lowercased()
            } else {
                print("Preferred OAuth2 flow (authcode | localhostauthcode | devicecode): ", terminator: "")
                guard let inputFlow = readLine()?.lowercased(),
                      ["authcode", "localhostauthcode", "devicecode"].contains(inputFlow) else {
                    print("Error: Invalid auth flow")
                    OAuth2CLI.exit(withError: ExitCode(1))
                }
                flow = inputFlow
            }
            
            // Create new token data
            token = TokenData(
                registration: registration,
                authflow: flow,
                email: email,
                accessToken: "",
                accessTokenExpiration: "",
                refreshToken: ""
            )
            
            // Save the initial token data
            try KeychainManager.shared.saveOrUpdateToken(token)
        }
        
        let registration = registrations[token.registration]!
        if authflow == nil {
            authflow = token.authflow
        }
        
        var baseparams: [String: String] = ["client_id": registration.clientId]

        // Microsoft uses 'tenant', but Google does not
        if let tenant = registration.tenant {
            baseparams["tenant"] = tenant
        }

        if authorize {
            var p = baseparams
            p["scope"] = registration.scope
            
            if authflow == "authcode" {
                var verifierData = Data(count: 90)
                _ = verifierData.withUnsafeMutableBytes { ptr in
                    SecRandomCopyBytes(kSecRandomDefault, 90, ptr.baseAddress!)
                }
                
                // Base64 encode and make URL safe
                let verifier = verifierData.base64EncodedString()
                        .replacingOccurrences(of: "+", with: "-")
                        .replacingOccurrences(of: "/", with: "_")
                    
                // Get SHA256 digest
                let digest = SHA256.hash(data: Data(verifier.utf8))
                
                // Convert digest to base64 and make URL safe
                let digestData = Data(digest)
                let base64Digest = digestData.base64EncodedString()
                    .replacingOccurrences(of: "+", with: "-")
                    .replacingOccurrences(of: "/", with: "_")
                
                // Remove last character
                let challenge = String(base64Digest.dropLast())

                let redirectUri = registration.redirectUri
                
                p.merge([
                    "login_hint": token.email,
                    "response_type": "code",
                    "redirect_uri": redirectUri,
                    "code_challenge": challenge,
                    "code_challenge_method": "S256"
                ], uniquingKeysWith: { (_, last) in last })

                print((registration.authorizeEndpoint + "?" + p.map { "\($0)=\($1)" }
                    .joined(separator: "&")
                    .addingPercentEncoding(withAllowedCharacters: .urlQueryAllowed)!
                    .replacingOccurrences(of: "/", with: "%2F")
                    .replacingOccurrences(of: ":", with: "%3A")
                    .replacingOccurrences(of: "@", with: "%40")))

                print("Visit displayed URL to retrieve authorization code. Enter code from server (might be in browser address bar): ")
                guard let line1 = readLine(), let line2 = readLine()
                else {
                    OAuth2CLI.exit(withError: ExitCode(1))
                }
                let authcode = line1 + line2
                if debug {
                    print("Using authcode: \(authcode)")
                }
//                let authcode = readLine()!

                if authcode.isEmpty {
                    print("Did not obtain an authcode.")
                    OAuth2CLI.exit(withError: ExitCode(1))
                }

                p.removeValue(forKey: "response_type")
                p.removeValue(forKey: "login_hint")
                p.removeValue(forKey: "code_challenge")
                p.removeValue(forKey: "code_challenge_method")
                p.merge([
                    "grant_type": "authorization_code",
                    "code": authcode,
                    "client_secret": registration.clientSecret ?? "",
                    "code_verifier": verifier
                ], uniquingKeysWith: { (_, last) in last })

                print("Exchanging the authorization code for an access token")
                let url = URL(string: registration.tokenEndpoint)!
                var request = URLRequest(url: url)
                request.httpMethod = "POST"
                request.httpBody = p.map { "\($0)=\($1)" }
                    .joined(separator: "&")
                    .replacingOccurrences(of: " ", with: "+")
                    .addingPercentEncoding(withAllowedCharacters: .urlQueryAllowed)!
                    .replacingOccurrences(of: "/", with: "%2F")
                    .replacingOccurrences(of: ":", with: "%3A")
                    .data(using: .utf8)
                
                if debug {
                    if let requestString = String(data: request.httpBody!, encoding: .utf8) {
                        print(requestString)
                    }
                }
                
                let (data, response) = try await URLSession.shared.data(for: request)
                
                if debug {
                    print("Request complete")
                }
                
                guard let httpResponse = response as? HTTPURLResponse, httpResponse.statusCode == 200 else {
                    print("Failed to exchange the authorization code for an access token")
                    OAuth2CLI.exit(withError: ExitCode(1))
                }
                
                if debug {
                    print("Got response")
                }
                
                guard let tokenResponse = try? JSONDecoder().decode(TokenResponse.self, from: data) else {
                    print("Failed to parse the response")
                    OAuth2CLI.exit(withError: ExitCode(1))
                }
                
                if debug {
                    if let responseString = String(data: data, encoding: .utf8) {
                        print(responseString)
                    }
                }
                
                if let error = tokenResponse.error {
                    print(error)
                    if let errorDescription = tokenResponse.errorDescription {
                        print(errorDescription)
                    }
                    OAuth2CLI.exit(withError: ExitCode(1))
                }
                
                do {
                    try token.updateTokens(from: tokenResponse)
                    try KeychainManager.shared.saveOrUpdateToken(token)
                } catch let error {
                    print("Failed to update the tokens")
                    print(error)
                    OAuth2CLI.exit(withError: ExitCode(1))
                }
            } else {
                print("ERROR: Unknown OAuth2 flow \"\(token.authflow)\". Delete token file and start over.")
                OAuth2CLI.exit(withError: ExitCode(1))
            }
        }
        
        if !token.isAccessTokenValid {
            if verbose {
                print("NOTICE: Invalid or expired access token; using refresh token to obtain new access token.")
            }
            guard !token.refreshToken.isEmpty else {
                print("ERROR: No refresh token. Run script with \"--authorize\".")
                OAuth2CLI.exit(withError: ExitCode(1))
            }

            var p = baseparams
            p.merge([
                "client_secret": registration.clientSecret ?? "",
                "refresh_token": token.refreshToken,
                "grant_type": "refresh_token"
            ], uniquingKeysWith: { (_, new) in new })

            let url = URL(string: registration.tokenEndpoint)!
            var request = URLRequest(url: url)
            request.httpMethod = "POST"
            request.httpBody = p.map { "\($0)=\($1)" }.joined(separator: "&").data(using: .utf8)
            
            let (data, response) = try await URLSession.shared.data(for: request)
            
            guard let httpResponse = response as? HTTPURLResponse, httpResponse.statusCode == 200 else {
                print("Failed to renew with refresh token")
                OAuth2CLI.exit(withError: ExitCode(1))
            }
            
            guard let tokenResponse = try? JSONDecoder().decode(TokenResponse.self, from: data) else {
                print("Failed to parse the response")
                OAuth2CLI.exit(withError: ExitCode(1))
            }
            
            if debug {
                if let responseString = String(data: data, encoding: .utf8) {
                    print(responseString)
                }
            }
            
            if let error = tokenResponse.error {
                print(error)
                if let errorDescription = tokenResponse.errorDescription {
                    print(errorDescription)
                }
                OAuth2CLI.exit(withError: ExitCode(1))
            }
            
            do {
                try token.updateTokens(from: tokenResponse)
                try KeychainManager.shared.saveOrUpdateToken(token)
            } catch let error {
                print("Failed to update access token")
                print(error)
                OAuth2CLI.exit(withError: ExitCode(1))
            }
        }

        if !token.isAccessTokenValid {
            print("ERROR: No valid access token. This should not be able to happen.")
            OAuth2CLI.exit(withError: ExitCode(1))
        }

        if verbose {
            print("Access Token: ", terminator: "")
        }
        print(token.accessToken)
    }
}
