import unittest
from unittest.mock import patch
from main import scan_file_with_yara

class TestScanFileWithYara(unittest.TestCase):

    @patch("builtins.open", create=True)
    @patch("yara.compile")
    def test_scan_file_clean(self, mock_compile, mock_open):
        # Mock the rule file content
        mock_open.return_value.__enter__.return_value.read.return_value = """
        rule CleanFile {
            strings:
                $magic_string = "clean_string"
            condition:
                $magic_string
        }
        """

        # Mock the YARA rules match
        mock_compile.return_value.match.return_value = []

        file_path = "check.exe"
        rule_file = "malware.yar"
        expected_output = f"File '{file_path}' is clean. No matches found."

        with patch("builtins.print") as mock_print:
            scan_file_with_yara(file_path, rule_file)

            mock_compile.assert_called_once_with(source=mock_open.return_value.__enter__.return_value.read.return_value)
            mock_compile.return_value.match.assert_called_once_with(filepath=file_path)
            mock_print.assert_called_once_with(expected_output)

if __name__ == "__main__":
    unittest.main()