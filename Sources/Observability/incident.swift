import Foundation
import HTTP

public enum IncidentNotificationKind: String, Sendable, Codable {
    case opened
    case recovered
}

public struct IncidentNotification: Sendable {
    public let kind: IncidentNotificationKind
    public let incidentId: UUID
    public let ruleId: String
    public let ruleTitle: String
    public let serviceName: String
    public let scope: String
    public let openedAt: Date
    public let lastMatchedAt: Date
    public let notifiedAt: Date
    public let matchedCount: Int
    public let totalCount: Int
    public let ratio: Double
    public let sampleRequestIds: [String]
    public let latestFailure: HTTPFailure?

    public init(
        kind: IncidentNotificationKind,
        incidentId: UUID,
        ruleId: String,
        ruleTitle: String,
        serviceName: String,
        scope: String,
        openedAt: Date,
        lastMatchedAt: Date,
        notifiedAt: Date,
        matchedCount: Int,
        totalCount: Int,
        ratio: Double,
        sampleRequestIds: [String],
        latestFailure: HTTPFailure?
    ) {
        self.kind = kind
        self.incidentId = incidentId
        self.ruleId = ruleId
        self.ruleTitle = ruleTitle
        self.serviceName = serviceName
        self.scope = scope
        self.openedAt = openedAt
        self.lastMatchedAt = lastMatchedAt
        self.notifiedAt = notifiedAt
        self.matchedCount = matchedCount
        self.totalCount = totalCount
        self.ratio = ratio
        self.sampleRequestIds = sampleRequestIds
        self.latestFailure = latestFailure
    }
}
