import os

def detect_suspicious_executables(directory):
    suspicious_extensions = [".exe", ".dll", ".sys"]

    # Get a list of files in the specified directory
    files_in_directory = os.listdir(directory)

    # Filter files with suspicious extensions
    suspicious_files = [file for file in files_in_directory if os.path.splitext(file)[1].lower() in suspicious_extensions]

    if suspicious_files:
        print("Suspicious executable files found:")
        for file in suspicious_files:
            print(file)
    else:
        print("No suspicious executable files found in the directory.")


import unittest
from unittest.mock import patch, call

class TestDetectSuspiciousExecutables(unittest.TestCase):

    @patch("os.listdir")
    def test_detect_suspicious_files_found(self, mock_listdir):
        # Mock the list of files in the directory
        mock_listdir.return_value = [
            "check.exe",
            "file3.dll",
            "file4.sys",
        ]

        directory = "D:\\3rd-sem\\programming\\project\\tapash"

        with patch("builtins.print") as mock_print:
            detect_suspicious_executables(directory)

            mock_listdir.assert_called_once_with(directory)
            mock_print.assert_has_calls([
                call("Suspicious executable files found:"),
                call("check.exe"),
                call("file3.dll"),
                call("file4.sys")
            ])

if __name__ == "__main__":
    unittest.main()