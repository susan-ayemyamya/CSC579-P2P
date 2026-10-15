
import statistics
import time
import unittest

from src.message import canonical_message
from src.security import calculate_hmac, verify_hmac


SECRET_KEY = b"demo-shared-key-change-later"
NUMBER_OF_TESTS = 1000


class TestHMACPerformance(unittest.TestCase):

    def test_hmac_verification_performance(self):
        message = canonical_message(
            "Peer B",
            "Performance test message",
        )
        tag = calculate_hmac(message, SECRET_KEY)

        # Warm up the verification function.
        verify_hmac(message, SECRET_KEY, tag)

        durations = []

        for _ in range(NUMBER_OF_TESTS):
            start = time.perf_counter()

            result = verify_hmac(
                message,
                SECRET_KEY,
                tag,
            )

            end = time.perf_counter()

            self.assertTrue(result)
            durations.append((end - start) * 1000)

        print("\nHMAC Verification Performance")
        print(f"Successful verifications: {len(durations)}")
        print(f"Average time: {statistics.mean(durations):.6f} ms")
        print(f"Median time:  {statistics.median(durations):.6f} ms")
        print(f"Minimum time: {min(durations):.6f} ms")
        print(f"Maximum time: {max(durations):.6f} ms")


if __name__ == "__main__":
    unittest.main(verbosity=2)
