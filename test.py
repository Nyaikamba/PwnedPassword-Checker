import unittest
import requests
import hashlib

# Unit tests
import checkmypass


class TestCheckMyPass(unittest.TestCase):

    def test_request_api_data_received(self):
        # Test that data is being received from API
        # Response code 200 means data is being received

        test_head = 'AAF4C'
        response = requests.get('https://api.pwnedpasswords.com/range/' + test_head)

        self.assertEqual(response.status_code, 200)

    def test_pwned_pass_check(self):
        # Hashes not in uppercase return no results

        test_password = 'aaf4c61ddcc5e8a2dabede0f3b482cd9aea9434d'
        test_sha1_pass = (hashlib.sha1(test_password.encode('utf-8')).hexdigest())
        result = checkmypass.pwned_pass_check(test_sha1_pass)
        self.assertEqual(result, 0)


if __name__ == '__main__':
    unittest.main()
