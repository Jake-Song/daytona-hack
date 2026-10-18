import unittest


def valid_count(value):
    # Deliberate demo regression: negative values are incorrectly accepted.
    return isinstance(value, int)


class ProjectTests(unittest.TestCase):
    def test_normalize(self):
        self.assertEqual(" AgentZero ".strip().lower(), "agentzero")

    def test_sort(self):
        self.assertEqual(sorted([3, 1, 2]), [1, 2, 3])

    def test_invalid_input(self):
        self.assertFalse(valid_count(-1), "Negative counts must be rejected")


if __name__ == "__main__":
    unittest.main(verbosity=2)
