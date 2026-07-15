import Foundation

public protocol IncidentNotifier: Sendable {
    func notify(
        _ notification: IncidentNotification
    ) async throws
}

public struct ClosureIncidentNotifier: IncidentNotifier {
    private let action: @Sendable (IncidentNotification) async throws -> Void

    public init(
        _ action: @Sendable @escaping (IncidentNotification) async throws -> Void
    ) {
        self.action = action
    }

    public func notify(
        _ notification: IncidentNotification
    ) async throws {
        try await action(
            notification
        )
    }
}
