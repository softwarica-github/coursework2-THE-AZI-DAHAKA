import yara
import os
import olefile
import psutil
import winreg
import re
import socket

def user_choice():
    print("Select a scan option:")
    print("1. Scan executable files for known malware signatures")
    print("2. Detect executables based on suspicious file extensions")
    print("3. Flag files with suspicious magic bytes")
    print("4. Detect Office macros with auto-execute functions")
    print("5. Detect suspicious process injections")
    print("6. Detect access to sensitive registry keys")
    print("7. Detect keylogger functionality")
    print("8. Scan files for C2 domain names")
    print("0. Exit")

    try:
        choice = int(input("Enter your choice (0-8): "))
        if 0 <= choice <= 8:
            return choice
        else:
            print("Invalid choice. Please enter a number between 0 and 8.")
            return user_choice()
    except ValueError:
        print("Invalid input. Please enter a valid number.\n")
        return user_choice()
    
def scan_file_with_yara(file_path, rule_file):
    try:
        # Read YARA rules from the rule file
        with open(rule_file, 'r') as file:
            yara_rules = file.read()

        # Compile YARA rules
        rules = yara.compile(source=yara_rules)

        # Scan the file with YARA rules
        matches = rules.match(filepath=file_path)

        # Check if there are any matches
        if matches:
            print(f"File '{file_path}' is flagged as suspicious. Matched rules:")
            for match in matches:
                print(match.rule)
        else:
            print(f"File '{file_path}' is clean. No matches found.")

    except Exception as e:
        print(f"Error while scanning file: {e}")

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

def flag_files_with_suspicious_magic_bytes(directory):
    suspicious_file_formats = {
        # Magic bytes for executable files
        ".exe": b'\x4D\x5A',        # 'MZ' (DOS header)
        ".dll": b'\x4D\x5A',        # 'MZ' (DOS header)
        ".sys": b'\x4D\x5A',        # 'MZ' (DOS header)

        # Magic bytes for ZIP files
        ".zip": b'\x50\x4B\x03\x04',    # 'PK\x03\x04'

        # Magic bytes for Office documents
        ".docx": b'\x50\x4B\x03\x04',   # 'PK\x03\x04' (ZIP format, DOCX is a ZIP archive)
        ".xlsx": b'\x50\x4B\x03\x04',   # 'PK\x03\x04' (ZIP format, XLSX is a ZIP archive)
        ".pptx": b'\x50\x4B\x03\x04',   # 'PK\x03\x04' (ZIP format, PPTX is a ZIP archive)

        # Add more magic bytes for other suspicious file formats here
    }

    # Get a list of files in the specified directory
    files_in_directory = os.listdir(directory)

    for file in files_in_directory:
        file_path = os.path.join(directory, file)

        # Open the file in binary mode and read the first few bytes (magic bytes)
        with open(file_path, 'rb') as f:
            file_magic_bytes = f.read(4)

        # Check if the magic bytes match any of the suspicious file formats
        for format_ext, magic_bytes in suspicious_file_formats.items():
            if file_magic_bytes.startswith(magic_bytes):
                print(f"Flagged file '{file}' as suspicious with magic bytes for {format_ext} format.")

def detect_office_macros_with_auto_execute(directory):
    office_extensions = [".doc", ".docm", ".dot", ".dotm", ".xls", ".xlsm", ".xlt", ".xltm", ".ppt", ".pptm", ".pot", ".potm"]

    for file in os.listdir(directory):
        file_path = os.path.join(directory, file)

        if os.path.isfile(file_path) and os.path.splitext(file_path)[1].lower() in office_extensions:
            with olefile.OleFileIO(file_path) as ole:
                if ole.exists('macros/vba') or ole.exists('Macros') or ole.exists('_VBA_PROJECT'):
                    print(f"File '{file}' contains Office macros:")

                    # Check for auto-execute functions
                    vba_code = ole.openstream('macros/vba') if ole.exists('macros/vba') else ole.openstream('Macros')
                    if "autoexec" in vba_code.read().decode("latin-1"):
                        print("Auto-execute function found in the macro.")
                    else:
                        print("No auto-execute function found in the macro.")

def detect_suspicious_process_injections():
    # Get a list of running processes
    running_processes = psutil.process_iter(attrs=['pid', 'name', 'cmdline'])

    # List of suspicious process names that may indicate process injection
    suspicious_process_names = [
        "svchost.exe",   # Legitimate, but often targeted for injection
        "lsass.exe",     # Legitimate, but often targeted for injection
        "explorer.exe",  # Legitimate, but sometimes abused for injection
    ]

    for process in running_processes:
        process_name = process.info['name']
        process_cmdline = process.info['cmdline']

        # Check if the process name matches any suspicious process names
        if process_name.lower() in suspicious_process_names:
            print(f"Absuable process detected: {process_name} (PID: {process.info['pid']})")

            # Check if cmdline is a list
            if isinstance(process_cmdline, list):
                print(f"Command Line: {' '.join(process_cmdline)}")
            else:
                print(f"Command Line: {process_cmdline}")

            print()

def detect_sensitive_registry_access():
    # List of sensitive registry keys
    sensitive_keys = [
        r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
        r"SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce",
        r"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run",
        r"SOFTWARE\Microsoft\Windows\CurrentVersion\RunServices",
        r"SOFTWARE\Microsoft\Windows\CurrentVersion\RunServicesOnce",
        r"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer\RunServices",
        r"SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnceEx",
        r"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer\RunOnce",
        r"SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnceEx",
        r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\Userinit",
        r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\Shell",
        r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\System",
        # Add more sensitive registry keys as needed
    ]

    for key_path in sensitive_keys:
        try:
            key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, key_path, 0, winreg.KEY_READ | winreg.KEY_WOW64_64KEY)
            print(f"Access to sensitive registry key '{key_path}' detected.")
            winreg.CloseKey(key)
        except FileNotFoundError:
            print(f"Sensitive registry key '{key_path}' not found.")

def detect_keylogger_functionality():
    suspicious_processes = []

    for process in psutil.process_iter(['pid', 'name']):
        process_name = process.info['name'].lower()
        if "keylogger" in process_name or "hook" in process_name:
            suspicious_processes.append(process.info['name'])

    if suspicious_processes:
        print("Potential keylogger functionality detected in the following processes:")
        for process_name in suspicious_processes:
            print(f" - {process_name}")
    else:
        print("No potential keylogger functionality detected.")

def is_valid_domain(domain_name):
    try:
        # Resolve the domain name to an IP address
        ip_address = socket.gethostbyname(domain_name)
        # If the domain name can be resolved, it is considered valid
        return True
    except socket.gaierror:
        # If the domain name cannot be resolved, it is considered invalid
        return False

def scan_file_for_c2_domain_names(file_path):
    try:
        with open(file_path, 'r', encoding='utf-8', errors='ignore') as file:
            content = file.read()
            # Regular expression to match domain names and IP addresses
            domain_regex = r'[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}'
            c2_domain_names = set(re.findall(domain_regex, content))

            valid_c2_domain_names = set()
            for domain_name in c2_domain_names:
                if is_valid_domain(domain_name):
                    valid_c2_domain_names.add(domain_name)

            if valid_c2_domain_names:
                print(f"Potential C2 domain names detected in '{file_path}':")
                for domain_name in valid_c2_domain_names:
                    print(f" - {domain_name}")
            else:
                print(f"No valid C2 domain names found in '{file_path}'.")

    except Exception as e:
        print(f"Error while scanning file '{file_path}': {e}")

def scan_files_in_directory(directory_path):
    for root, dirs, files in os.walk(directory_path):
        for file in files:
            file_path = os.path.join(root, file)
            try:
                scan_file_for_c2_domain_names(file_path)
            except Exception as e:
                print(f"Error while scanning file '{file_path}': {e}")

if __name__ == "__main__":
    choice = user_choice()
    
    if choice == 0:
        print("Exiting...")
    elif choice == 1:
        print("You chose to scan executable files for known malware signatures.")
        file_to_scan = input("Enter the path to the executable file to scan: ")
        yara_rule_file = "malware.yar"  # Replace with your YARA rule file
        scan_file_with_yara(file_to_scan, yara_rule_file)
    elif choice == 2:
        print("You chose to detect executables based on suspicious file extensions.")
        directory_to_scan = input("Enter the path to the directory to scan: ")
        if os.path.isdir(directory_to_scan):
            detect_suspicious_executables(directory_to_scan)
        else:
            print("Invalid directory path. Please enter a valid directory path.")
    elif choice == 3:
        print("You chose to flag files with suspicious magic bytes.")
        directory_to_scan = input("Enter the path to the directory to scan: ")

        if os.path.isdir(directory_to_scan):
            flag_files_with_suspicious_magic_bytes(directory_to_scan)
        else:
            print("Invalid directory path. Please enter a valid directory path.")
    elif choice == 4:
        print("You chose to detect Office macros with auto-execute functions.")
        directory_to_scan = input("Enter the path to the directory to scan: ")

        if os.path.isdir(directory_to_scan):
            detect_office_macros_with_auto_execute(directory_to_scan)
        else:
            print("Invalid directory path. Please enter a valid directory path.")
    elif choice == 5:
        print("You chose to detect suspicious process injections.")
        detect_suspicious_process_injections()
    elif choice == 6:
        print("You chose to detect access to sensitive registry keys.")
        detect_sensitive_registry_access()
    elif choice == 7:
        print("You chose to detect keylogger functionality.")
        detect_keylogger_functionality()
    elif choice == 8:
        print("You chose to scan files for C2 domain names.")
        directory_path = input("Enter the path to the directory to scan: ")
        scan_files_in_directory(directory_path)
    else:
        print("Invalid choice. Please enter a valid choice.\n")
        