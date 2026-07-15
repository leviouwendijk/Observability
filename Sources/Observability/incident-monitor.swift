import Foundation
import HTTP

public actor IncidentMonitor {
    private struct BucketKey: Hashable, Sendable {
        let ruleId: String
        let scope: String
    }

    private struct Sample: Sendable {
        let timestamp: Date
        let matched: Bool
        let requestId: String?
        let failure: HTTPFailure?
    }

    private struct ActiveIncident: Sendable {
        let id: UUID
        let key: BucketKey
        let rule: IncidentRule
        let serviceName: String
        let openedAt: Date
        var lastMatchedAt: Date
        var matchedCount: Int
        var totalCount: Int
        var ratio: Double
        var sampleRequestIds: [String]
        var latestFailure: HTTPFailure?
    }

    private let rules: [IncidentRule]
    private let notifier: any IncidentNotifier
    private let diagnostics: @Sendable (String) -> Void

    private var buckets: [BucketKey: [Sample]] = [:]
    private var active: [BucketKey: ActiveIncident] = [:]

    public init(
        rules: [IncidentRule],
        notifier: any IncidentNotifier,
        diagnostics: @Sendable @escaping (String) -> Void = {
            print("[observability] \($0)")
        }
    ) {
        self.rules = rules
        self.notifier = notifier
        self.diagnostics = diagnostics
    }

    public func record(
        _ event: HTTPActivityEvent
    ) async {
        for rule in rules {
            let scope = scopeValue(
                for: rule.scope,
                event: event
            )

            let key = BucketKey(
                ruleId: rule.id,
                scope: scope
            )

            let matched = rule.match.matches(
                event
            )

            switch rule.threshold {
            case .immediate,
                 .count:
                guard matched else {
                    continue
                }

            case .ratio:
                break
            }

            var samples = buckets[key] ?? []
            samples.append(
                Sample(
                    timestamp: event.timestamp,
                    matched: matched,
                    requestId: event.requestId,
                    failure: event.failure
                )
            )

            let cutoff = event.timestamp.addingTimeInterval(
                -rule.window
            )

            samples.removeAll {
                $0.timestamp < cutoff
            }

            buckets[key] = samples

            let evaluation = evaluate(
                rule: rule,
                samples: samples
            )

            guard evaluation.triggered else {
                continue
            }

            if var incident = active[key] {
                incident.lastMatchedAt = event.timestamp
                incident.matchedCount = evaluation.matchedCount
                incident.totalCount = evaluation.totalCount
                incident.ratio = evaluation.ratio
                incident.sampleRequestIds = evaluation.sampleRequestIds
                incident.latestFailure = evaluation.latestFailure
                active[key] = incident
                continue
            }

            let incident = ActiveIncident(
                id: UUID(),
                key: key,
                rule: rule,
                serviceName: event.serviceName,
                openedAt: event.timestamp,
                lastMatchedAt: event.timestamp,
                matchedCount: evaluation.matchedCount,
                totalCount: evaluation.totalCount,
                ratio: evaluation.ratio,
                sampleRequestIds: evaluation.sampleRequestIds,
                latestFailure: evaluation.latestFailure
            )

            active[key] = incident

            await send(
                notification(
                    for: incident,
                    kind: .opened,
                    now: event.timestamp
                )
            )
        }
    }

    public func tick(
        now: Date = Date()
    ) async {
        let recoverable = active.values.filter {
            now.timeIntervalSince(
                $0.lastMatchedAt
            ) >= $0.rule.recoveryInterval
        }

        for incident in recoverable {
            active.removeValue(
                forKey: incident.key
            )

            buckets.removeValue(
                forKey: incident.key
            )

            await send(
                notification(
                    for: incident,
                    kind: .recovered,
                    now: now
                )
            )
        }
    }

    private func scopeValue(
        for scope: IncidentRuleScope,
        event: HTTPActivityEvent
    ) -> String {
        switch scope {
        case .service:
            return event.serviceName

        case .route:
            return "\(event.serviceName)|\(event.routePattern ?? event.path)"

        case .failure:
            return "\(event.serviceName)|\(event.failure?.code ?? "status.\(event.status.code)")"

        case .dependency:
            return "\(event.serviceName)|\(event.failure?.dependency ?? "unknown")"
        }
    }

    private func evaluate(
        rule: IncidentRule,
        samples: [Sample]
    ) -> (
        triggered: Bool,
        matchedCount: Int,
        totalCount: Int,
        ratio: Double,
        sampleRequestIds: [String],
        latestFailure: HTTPFailure?
    ) {
        let matched = samples.filter {
            $0.matched
        }

        let matchedCount = matched.count
        let totalCount = samples.count
        let ratio = totalCount == 0
            ? 0
            : Double(matchedCount) / Double(totalCount)

        let triggered: Bool

        switch rule.threshold {
        case .immediate:
            triggered = matchedCount >= 1

        case .count(let minimum):
            triggered = matchedCount >= minimum

        case .ratio(
            let minimumFailures,
            let minimumTotal,
            let minimumRatio
        ):
            triggered = matchedCount >= minimumFailures
                && totalCount >= minimumTotal
                && ratio >= minimumRatio
        }

        let requestIds = Array(
            matched
                .compactMap {
                    $0.requestId
                }
                .suffix(5)
        )

        let latestFailure = matched
            .reversed()
            .compactMap {
                $0.failure
            }
            .first

        return (
            triggered,
            matchedCount,
            totalCount,
            ratio,
            requestIds,
            latestFailure
        )
    }

    private func notification(
        for incident: ActiveIncident,
        kind: IncidentNotificationKind,
        now: Date
    ) -> IncidentNotification {
        IncidentNotification(
            kind: kind,
            incidentId: incident.id,
            ruleId: incident.rule.id,
            ruleTitle: incident.rule.title,
            serviceName: incident.serviceName,
            scope: incident.key.scope,
            openedAt: incident.openedAt,
            lastMatchedAt: incident.lastMatchedAt,
            notifiedAt: now,
            matchedCount: incident.matchedCount,
            totalCount: incident.totalCount,
            ratio: incident.ratio,
            sampleRequestIds: incident.sampleRequestIds,
            latestFailure: incident.latestFailure
        )
    }

    private func send(
        _ notification: IncidentNotification
    ) async {
        do {
            try await notifier.notify(
                notification
            )
        } catch {
            diagnostics(
                "Notification failed for \(notification.incidentId): \(error.localizedDescription)"
            )
        }
    }
}
