import unittest


class ProjectTests(unittest.TestCase):
    def test_sum(self):
        self.assertEqual(sum([2, 3, 5]), 10)

    def test_sort(self):
        self.assertEqual(sorted([3, 1, 2]), [1, 2, 3])

    def test_normalize(self):
        self.assertEqual(" AgentZero ".strip().lower(), "agentzero")


if __name__ == "__main__":
    unittest.main(verbosity=2)
