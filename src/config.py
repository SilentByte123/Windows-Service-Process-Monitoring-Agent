"""
Detection rules and defaults for the Windows Service & Process Monitoring Agent.

Edit these lists to tune for your environment. Values are case-insensitive.
"""
from pathlib import Path

DEFAULT_WHITELIST = {
    "system","smss.exe","csrss.exe","wininit.exe","services.exe","lsass.exe","lsm.exe",
    "svchost.exe","winlogon.exe","explorer.exe","spoolsv.exe","taskhostw.exe","dwm.exe",
    "audiodg.exe","searchui.exe","runtimebroker.exe","conhost.exe",
}

DEFAULT_BLACKLIST = {
    "mimikatz.exe","procdump.exe","psexec.exe","nc.exe","netcat.exe","cobaltstrike.exe","meterpreter.exe",
}

SUSPICIOUS_PARENT_CHILD = {
    "winword.exe": ["cmd.exe","powershell.exe","wscript.exe","cscript.exe","mshta.exe"],
    "excel.exe": ["cmd.exe","powershell.exe","wscript.exe","cscript.exe"],
    "outlook.exe": ["cmd.exe","powershell.exe","wscript.exe"],
    "acrord32.exe": ["powershell.exe","cmd.exe"],
    "teams.exe": ["powershell.exe","cmd.exe"],
    "zoom.exe": ["powershell.exe","cmd.exe"],
    "chrome.exe": ["cmd.exe","powershell.exe","wscript.exe"],
    "firefox.exe": ["cmd.exe","powershell.exe","wscript.exe"],
}

USER_WRITABLE_DIR_KEYWORDS = [
    "\\appdata\\local\\temp","\\appdata\\roaming","\\windows\\temp","\\users\\public","\\downloads",
]

SERVICE_SUSPICIOUS_PATH_KEYWORDS = [
    "\\temp\\","\\appdata\\","\\users\\public\\","\\$recycle.bin\\",
]

SERVICE_START_MODE_SUSPICIOUS = {"auto","automatic"}

def load_custom_list(path: Path) -> set[str]:
    if not path.exists():
        return set()
    names: set[str] = set()
    for line in path.read_text(encoding="utf-8", errors="ignore").splitlines():
        line = line.strip()
        if line and not line.startswith("#"):
            names.add(line.lower())
    return names
