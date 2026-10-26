from __future__ import annotations

import unittest

from highwall.circuit import CircuitBreaker


class Clock:
    def __init__(self) -> None:
        self.now = 100.0

    def __call__(self) -> float:
        return self.now

    def advance(self, seconds: float) -> None:
        self.now += seconds


class CircuitBreakerTests(unittest.TestCase):
    def test_opens_after_failure_threshold(self) -> None:
        clock = Clock()
        breaker = CircuitBreaker(2, 10.0, 30.0, clock=clock)

        first = breaker.allow()
        self.assertEqual(first.state, "closed")
        self.assertFalse(breaker.record_failure(first.token))
        self.assertEqual(breaker.current_state(), "closed")

        second = breaker.allow()
        self.assertTrue(breaker.record_failure(second.token))
        self.assertEqual(breaker.current_state(), "open")
        self.assertEqual(breaker.open_events, 1)

    def test_open_state_returns_retry_after(self) -> None:
        clock = Clock()
        breaker = CircuitBreaker(1, 10.0, 12.5, clock=clock)
        decision = breaker.allow()
        self.assertTrue(breaker.record_failure(decision.token))

        rejected = breaker.allow()
        self.assertFalse(rejected.allowed)
        self.assertEqual(rejected.state, "open")
        self.assertAlmostEqual(rejected.retry_after, 12.5, places=3)
        self.assertEqual(rejected.state_code, 2)

    def test_half_open_admits_bounded_probes(self) -> None:
        clock = Clock()
        breaker = CircuitBreaker(1, 10.0, 5.0, half_open_max_requests=1, clock=clock)
        first = breaker.allow()
        self.assertTrue(breaker.record_failure(first.token))
        clock.advance(5.0)

        probe = breaker.allow()
        self.assertTrue(probe.allowed)
        self.assertEqual(probe.state, "half_open")
        self.assertEqual(probe.state_code, 1)
        rejected = breaker.allow()
        self.assertFalse(rejected.allowed)
        self.assertEqual(rejected.state, "half_open")
        self.assertAlmostEqual(rejected.retry_after, 1.0, places=3)

    def test_half_open_success_closes_and_increments_generation(self) -> None:
        clock = Clock()
        breaker = CircuitBreaker(1, 10.0, 5.0, clock=clock)
        first = breaker.allow()
        breaker.record_failure(first.token)
        clock.advance(5.0)
        probe = breaker.allow()

        self.assertTrue(breaker.record_success(probe.token))
        self.assertEqual(breaker.current_state(), "closed")
        self.assertEqual(breaker.half_open_events, 1)
        self.assertFalse(breaker.record_success(probe.token))

    def test_half_open_failure_reopens(self) -> None:
        clock = Clock()
        breaker = CircuitBreaker(1, 10.0, 5.0, clock=clock)
        first = breaker.allow()
        breaker.record_failure(first.token)
        clock.advance(5.0)
        probe = breaker.allow()

        self.assertTrue(breaker.record_failure(probe.token))
        self.assertEqual(breaker.current_state(), "open")
        self.assertEqual(breaker.open_events, 2)
        self.assertFalse(breaker.allow().allowed)

    def test_stale_token_cannot_change_new_state(self) -> None:
        clock = Clock()
        breaker = CircuitBreaker(1, 10.0, 30.0, clock=clock)
        stale = breaker.allow()
        self.assertTrue(breaker.record_failure(stale.token))

        self.assertFalse(breaker.record_success(stale.token))
        self.assertFalse(breaker.record_failure(stale.token))
        self.assertEqual(breaker.current_state(), "open")

    def test_failure_window_expires_old_failures(self) -> None:
        clock = Clock()
        breaker = CircuitBreaker(2, 10.0, 30.0, clock=clock)
        first = breaker.allow()
        self.assertFalse(breaker.record_failure(first.token))
        clock.advance(10.1)

        second = breaker.allow()
        self.assertFalse(breaker.record_failure(second.token))
        third = breaker.allow()
        self.assertTrue(breaker.record_failure(third.token))

    def test_success_resets_closed_state_failures(self) -> None:
        clock = Clock()
        breaker = CircuitBreaker(2, 10.0, 30.0, clock=clock)
        first = breaker.allow()
        breaker.record_failure(first.token)
        second = breaker.allow()
        breaker.record_success(second.token)
        third = breaker.allow()
        self.assertFalse(breaker.record_failure(third.token))
        self.assertEqual(breaker.current_state(), "closed")


if __name__ == "__main__":
    unittest.main()
