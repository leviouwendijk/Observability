import Foundation
import HTTP

public final class ObservationSystem: @unchecked Sendable {
    public let activity: HTTPActivityCallback

    private let continuation: AsyncStream<HTTPActivityEvent>.Continuation
    private let worker: Task<Void, Never>
    private let ticker: Task<Void, Never>

    public init(
        rules: [IncidentRule] = .standardAPI,
        notifier: any IncidentNotifier,
        bufferLimit: Int = 4_096,
        tickInterval: TimeInterval = 30,
        diagnostics: @Sendable @escaping (String) -> Void = {
            print("[observability] \($0)")
        }
    ) {
        let pair = AsyncStream<HTTPActivityEvent>.makeStream(
            bufferingPolicy: .bufferingNewest(
                bufferLimit
            )
        )

        let monitor = IncidentMonitor(
            rules: rules,
            notifier: notifier,
            diagnostics: diagnostics
        )

        self.continuation = pair.continuation
        self.activity = { event in
            let result = pair.continuation.yield(
                event
            )

            if case .dropped = result {
                diagnostics(
                    "Observation queue full; oldest buffered activity was dropped"
                )
            }
        }

        self.worker = Task {
            for await event in pair.stream {
                await monitor.record(
                    event
                )
            }
        }

        self.ticker = Task {
            let nanoseconds = UInt64(
                max(
                    tickInterval,
                    1
                ) * 1_000_000_000
            )

            while !Task.isCancelled {
                do {
                    try await Task.sleep(
                        nanoseconds: nanoseconds
                    )
                } catch {
                    break
                }

                await monitor.tick()
            }
        }
    }

    public func shutdown() async {
        continuation.finish()
        ticker.cancel()
        worker.cancel()

        _ = await worker.result
        _ = await ticker.result
    }

    deinit {
        continuation.finish()
        ticker.cancel()
        worker.cancel()
    }
}
