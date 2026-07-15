import Foundation
import HTTP

public enum IncidentRuleScope: String, Sendable, Codable {
    case service
    case route
    case failure
    case dependency
}

public enum IncidentRuleMatch: Sendable {
    case statusFamily(HTTPStatusFamily)
    case statusCodes(ClosedRange<Int>)
    case failureKinds(Set<HTTPFailureKind>)
    case failureSeverities(Set<HTTPFailureSeverity>)

    func matches(
        _ event: HTTPActivityEvent
    ) -> Bool {
        switch self {
        case .statusFamily(let family):
            return event.status.family == family

        case .statusCodes(let codes):
            return codes.contains(
                event.status.code
            )

        case .failureKinds(let kinds):
            guard let failure = event.failure else {
                return false
            }

            return kinds.contains(
                failure.kind
            )

        case .failureSeverities(let severities):
            guard let failure = event.failure else {
                return false
            }

            return severities.contains(
                failure.severity
            )
        }
    }
}

public enum IncidentRuleThreshold: Sendable {
    case immediate
    case count(Int)
    case ratio(
        minimumFailures: Int,
        minimumTotal: Int,
        minimumRatio: Double
    )
}

public struct IncidentRule: Sendable {
    public let id: String
    public let title: String
    public let scope: IncidentRuleScope
    public let match: IncidentRuleMatch
    public let threshold: IncidentRuleThreshold
    public let window: TimeInterval
    public let recoveryInterval: TimeInterval

    public init(
        id: String,
        title: String,
        scope: IncidentRuleScope,
        match: IncidentRuleMatch,
        threshold: IncidentRuleThreshold,
        window: TimeInterval,
        recoveryInterval: TimeInterval
    ) {
        self.id = id
        self.title = title
        self.scope = scope
        self.match = match
        self.threshold = threshold
        self.window = window
        self.recoveryInterval = recoveryInterval
    }
}

public extension Array where Element == IncidentRule {
    static var standardAPI: [IncidentRule] {
        [
            .init(
                id: "http.server-errors.repeated",
                title: "Repeated HTTP server errors",
                scope: .service,
                match: .statusFamily(.serverError),
                threshold: .count(3),
                window: 120,
                recoveryInterval: 600
            ),
            .init(
                id: "http.rate-limit.spike",
                title: "HTTP rate-limit spike",
                scope: .route,
                match: .statusCodes(429...429),
                threshold: .count(20),
                window: 300,
                recoveryInterval: 600
            ),
            .init(
                id: "http.operational-failure.repeated",
                title: "Repeated operational dependency failure",
                scope: .dependency,
                match: .failureKinds([
                    .dependency,
                    .database,
                    .tls,
                    .configuration
                ]),
                threshold: .count(2),
                window: 120,
                recoveryInterval: 600
            ),
            .init(
                id: "http.failure.critical",
                title: "Critical operational failure",
                scope: .failure,
                match: .failureSeverities([
                    .critical
                ]),
                threshold: .immediate,
                window: 60,
                recoveryInterval: 600
            )
        ]
    }

    static var standardAPIWithRatio: [IncidentRule] {
        standardAPI + [
            .init(
                id: "http.server-errors.ratio",
                title: "Elevated HTTP server-error ratio",
                scope: .service,
                match: .statusFamily(.serverError),
                threshold: .ratio(
                    minimumFailures: 10,
                    minimumTotal: 20,
                    minimumRatio: 0.10
                ),
                window: 300,
                recoveryInterval: 600
            )
        ]
    }
}
