import unittest
from unittest.mock import patch
from main import user_choice

class TestUserChoice(unittest.TestCase):

    @patch("builtins.input", side_effect=["3"])
    def test_valid_choice(self, mock_input):
        choice = user_choice()
        self.assertEqual(choice, 3)

    @patch("builtins.input", side_effect=["abc", "5"])
    def test_invalid_input_then_valid_choice(self, mock_input):
        choice = user_choice()
        self.assertEqual(choice, 5)

    @patch("builtins.input", side_effect=["-1", "1"])
    def test_negative_input_then_valid_choice(self, mock_input):
        choice = user_choice()
        self.assertEqual(choice, 1)

    @patch("builtins.input", side_effect=["12", "0"])
    def test_out_of_range_input_then_exit(self, mock_input):
        choice = user_choice()
        self.assertEqual(choice, 0)

if __name__ == "__main__":
    unittest.main()