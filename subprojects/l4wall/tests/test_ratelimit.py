from __future__ import annotations

import unittest

from l4wall.ratelimit import TokenBucket


class RateLimitTests(unittest.TestCase):
    def test_burst_then_refill(self) -> None:
        bucket = TokenBucket(rate=1.0, burst=2, now=0.0)
        self.assertTrue(bucket.allow(0.0))
        self.assertTrue(bucket.allow(0.0))
        self.assertFalse(bucket.allow(0.0))
        self.assertTrue(bucket.allow(1.0))
        self.assertFalse(bucket.allow(1.0))
        self.assertTrue(bucket.allow(2.0))

    def test_retry_after(self) -> None:
        bucket = TokenBucket(rate=2.0, burst=1, now=0.0)
        self.assertTrue(bucket.allow(0.0))
        self.assertAlmostEqual(bucket.retry_after(0.0), 0.5)


if __name__ == "__main__":
    unittest.main()

