import Foundation

#if canImport(FoundationNetworking)
import FoundationNetworking
#endif

import Cryptography

public enum MailerIncidentNotifierError: Error, LocalizedError {
    case invalidResponse
    case rejected(statusCode: Int)

    public var errorDescription: String? {
        switch self {
        case .invalidResponse:
            return "Mailer returned a non-HTTP response"

        case .rejected(let statusCode):
            return "Mailer rejected the incident notification with HTTP \(statusCode)"
        }
    }
}

public struct MailerIncidentNotifier: IncidentNotifier {
    private struct Recipients: Encodable {
        let to: [String]
        let cc: [String]?
        let bcc: [String]?
    }

    private struct EmailRequest: Encodable {
        let recipients: Recipients
        let from: String
        let subject: String
        let body: String
        let html: Bool
        let region: String?
        let reply_to: String?
        let attachments: [String]?
    }

    public let endpoint: URL
    public let bearerToken: String
    public let caCertificatePathSymbol: String
    public let allowedHost: String
    public let from: String
    public let recipients: [String]

    public init(
        endpoint: URL,
        bearerToken: String,
        caCertificatePathSymbol: String = "CA_CERT",
        allowedHost: String,
        from: String,
        recipients: [String]
    ) {
        self.endpoint = endpoint
        self.bearerToken = bearerToken
        self.caCertificatePathSymbol = caCertificatePathSymbol
        self.allowedHost = allowedHost
        self.from = from
        self.recipients = recipients
    }

    public func notify(
        _ notification: IncidentNotification
    ) async throws {
        let requestBody = EmailRequest(
            recipients: Recipients(
                to: recipients,
                cc: nil,
                bcc: nil
            ),
            from: from,
            subject: subject(
                for: notification
            ),
            body: body(
                for: notification
            ),
            html: false,
            region: nil,
            reply_to: nil,
            attachments: nil
        )

        var request = URLRequest(
            url: endpoint
        )

        request.httpMethod = "POST"
        request.setValue(
            "application/json",
            forHTTPHeaderField: "Content-Type"
        )
        request.setValue(
            "Bearer \(bearerToken)",
            forHTTPHeaderField: "Authorization"
        )
        request.httpBody = try JSONEncoder().encode(
            requestBody
        )

        let configuration = URLSessionConfiguration.ephemeral
        configuration.timeoutIntervalForRequest = 10
        configuration.timeoutIntervalForResource = 15

        let (_, response) = try await CryptographicCATrustedURLSession.data(
            for: request,
            caCertificatePathSymbol: caCertificatePathSymbol,
            allowedHost: allowedHost,
            policyMode: .basicX509,
            configuration: configuration
        )

        guard let http = response as? HTTPURLResponse else {
            throw MailerIncidentNotifierError.invalidResponse
        }

        guard (200..<300).contains(http.statusCode) else {
            throw MailerIncidentNotifierError.rejected(
                statusCode: http.statusCode
            )
        }
    }

    private func subject(
        for notification: IncidentNotification
    ) -> String {
        let prefix = notification.kind == .opened
            ? "ALERT"
            : "RECOVERED"

        return "[\(prefix)] \(notification.serviceName): \(notification.ruleTitle)"
    }

    private func body(
        for notification: IncidentNotification
    ) -> String {
        var lines: [String] = [
            "Incident: \(notification.incidentId.uuidString)",
            "State: \(notification.kind.rawValue)",
            "Service: \(notification.serviceName)",
            "Rule: \(notification.ruleId)",
            "Scope: \(notification.scope)",
            "Opened: \(notification.openedAt.formatted(.iso8601))",
            "Last match: \(notification.lastMatchedAt.formatted(.iso8601))",
            "Matched: \(notification.matchedCount)",
            "Observed: \(notification.totalCount)",
            "Ratio: \(String(format: "%.2f%%", notification.ratio * 100))"
        ]

        if !notification.sampleRequestIds.isEmpty {
            lines.append(
                "Request IDs: \(notification.sampleRequestIds.joined(separator: ", "))"
            )
        }

        if let failure = notification.latestFailure {
            lines.append(contentsOf: [
                "Failure code: \(failure.code)",
                "Failure kind: \(failure.kind.rawValue)",
                "Failure severity: \(failure.severity.rawValue)",
                "Dependency: \(failure.dependency ?? "-")",
                "Retryable: \(failure.retryable.map(String.init) ?? "-")",
                "Details: \(failure.message)"
            ])
        }

        return lines.joined(
            separator: "\n"
        )
    }
}
