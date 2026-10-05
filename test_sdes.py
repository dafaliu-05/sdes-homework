import unittest

from sdes import brute_force, decrypt, encrypt, generate_keys


class SDESTest(unittest.TestCase):
    def test_key_schedule_example(self):
        self.assertEqual(generate_keys("1010000010"), ("10100100", "01000011"))

    def test_encrypt_example(self):
        self.assertEqual(encrypt("11010111", "1010000010"), "10101000")

    def test_decrypt_example(self):
        self.assertEqual(decrypt("10101000", "1010000010"), "11010111")

    def test_round_trip_for_some_keys(self):
        keys = ("0000000000", "0000011111", "1010000010", "1111111111")
        for key in keys:
            for value in range(256):
                block = format(value, "08b")
                self.assertEqual(decrypt(encrypt(block, key), key), block)

    def test_brute_force(self):
        self.assertIn("1010000010", brute_force("11010111", "10101000"))

    def test_rejects_invalid_lengths_and_characters(self):
        with self.assertRaises(ValueError):
            encrypt("101", "1010000010")
        with self.assertRaises(ValueError):
            encrypt("11010111", "101000001x")


if __name__ == "__main__":
    unittest.main()
