import unittest

from http_detective import human_size


class HttpDetectiveTests(unittest.TestCase):
    def test_human_size_bytes(self):
        self.assertEqual(human_size("500"), "500 B")

    def test_human_size_kilobytes(self):
        self.assertEqual(human_size("2048"), "2.0 KB")

    def test_human_size_unknown(self):
        self.assertEqual(human_size(None), "unknown")


if __name__ == "__main__":
    unittest.main()
