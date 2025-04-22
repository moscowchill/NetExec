import random
import string
import re
import inspect
import os
import sys
import time


# Define plausible service names for use in tools like smbexec
PLAUSIBLE_SERVICE_NAMES = [
    "WinDriverSync",
    "DFSShareSync",
    "ChromeUpdate",
    "AdobeFlashHelper",
    "OfficeLicenseCheck",
    "NetworkConfigSvc",
    "SysHealthMonitor",
    "PrinterSpoolerFix",
    "WindowsBackupUtil",
    "JavaRuntimeSync",
    "AudioDriverSvc",
    "DiskOptimizerSvc",
]


# Define plausible usernames for guest/null sessions
PLAUSIBLE_USERNAMES = [
    "PrinterQueue",
    "svc_helpdesk",
    "svc_backup",
    "svc_temp",
    "svc_support",
    "svc_scanner",
    "intern",
    "reception",
    "HelpDesk",
    "guestuser",
    "training",
    "labuser",
    "Guest",
    "Anonymous",
    "PrintSpooler",
    "SQLServer",
    "SQLServerAgent",
    "SQLServerBrowser",
    "SQLServerImport",
    "SQLServerExport",
    "SQLServerReporting",
    "SQLServerAnalysis",
    "SQLServerFullText",
    "SQLServerIntegration",
    "SQLServerServiceBroker",
    "SQLServerReporting",
]


# Define plausible client hostnames for SMB connections
PLAUSIBLE_CLIENT_NAMES = [
    "HP-LaserJet-Pro",
    "Canon_Scanner_Office",
    "BRN_Printer",
    "EPSON-WF-Series",
    "DESKTOP-ScanSrv",
    "SonosZP",
    "LivingRoomSpeaker",
    "KitchenDisplay",
    "SecurityCam_FrontDoor",
    "NVR_System",
    "SolarEdgeInverter",
    "EnphaseEnvoy",
    "SmartThingsHub",
    "PhilipsHueBridge",
    "Netgear-NAS",
    "SynologyDS",
    "TP-Link_AP",
    "UniFi-AP-AC-Pro",
    "MyBookLive",
    "MEDIA-SERVER",
    "KONICA_MINOLTA_Bizhub",
    "Xerox-WorkCentre",
    "Ricoh-MP-CSeries",
    "Lexmark_Printer",
    "Kyocera_ECOSYS",
    "Sharp_MX_Series",
    "Roomba_LivingRoom",
    "ECOVACS-DEEBOT",
    "Nest_Thermostat",
    "ecobee_Office",
    "RaspberryPi_Media",
    "HomeAssistant",
    "PlexMediaServer",
    "Logitech_ConferenceCam",
    "Polycom_Trio",
    "Cisco_IP_Phone",
    "Yealink_DeskPhone",
    "AppleTV_Lobby",
    "FireStick_MeetingRoom",
    "Chromecast_BreakRoom",
    "roku-ultra",
    "Hikvision_Camera",
    "Axis_Doorbell",
    "myq-garage",
    "POS-Terminal-1",
]

def countdown_timer(min_delay=3, max_delay=6):
    """Generates a random delay and displays a countdown timer in the terminal."""
    duration = random.randint(min_delay, max_delay)
    for i in range(duration, 0, -1):
        # Use sys.stdout.write and carriage return to overwrite the line
        sys.stdout.write(f"\r[+] Applying tactical delay... {i}s remaining ")
        sys.stdout.flush()
        time.sleep(1)
    # Clear the countdown line after completion
    sys.stdout.write("\r" + " " * 30 + "\r")
    sys.stdout.flush()

def identify_target_file(target_file):
    with open(target_file) as target_file_handle:
        for i, line in enumerate(target_file_handle):
            if i == 1:
                if line.startswith("<NessusClientData"):
                    return "nessus"
                elif line.endswith("nmaprun>\n"):
                    return "nmap"

    return "unknown"


def gen_random_string(length=10):
    return "".join(random.sample(string.ascii_letters, int(length)))


def validate_ntlm(data):
    allowed = re.compile("^[0-9a-f]{32}", re.IGNORECASE)
    return bool(allowed.match(data))


def called_from_cmd_args():
    for stack in inspect.stack():
        if stack[3] == "print_host_info":
            return True
        if stack[3] == "plaintext_login" or stack[3] == "hash_login" or stack[3] == "kerberos_login":
            return True
        if stack[3] == "call_cmd_args":
            return True
    return False


# Stolen from https://github.com/pydanny/whichcraft/
def which(cmd, mode=os.F_OK | os.X_OK, path=None):
    """Find the path which conforms to the given mode on the PATH for a command.
    
    Given a command, mode, and a PATH string, return the path which conforms to the given mode on the PATH, or None if there is no such file.
    `mode` defaults to os.F_OK | os.X_OK. `path` defaults to the result of os.environ.get("PATH"), or can be overridden with a custom search path.
    Note: This function was backported from the Python 3 source code.
    """

    # Check that a given file can be accessed with the correct mode.
    # Additionally check that `file` is not a directory, as on Windows
    # directories pass the os.access check.
    def _access_check(fn, mode):
        return os.path.exists(fn) and os.access(fn, mode) and not os.path.isdir(fn)

    # If we're given a path with a directory part, look it up directly
    # rather than referring to PATH directories. This includes checking
    # relative to the current directory, e.g. ./script
    if os.path.dirname(cmd):
        if _access_check(cmd, mode):
            return cmd
        return None

    if path is None:
        path = os.environ.get("PATH", os.defpath)
    if not path:
        return None
    path = path.split(os.pathsep)

    files = [cmd]

    seen = set()
    for p in path:
        normdir = os.path.normcase(p)
        if normdir not in seen:
            seen.add(normdir)
            for thefile in files:
                name = os.path.join(p, thefile)
                if _access_check(name, mode):
                    return name
