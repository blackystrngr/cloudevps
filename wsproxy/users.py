"""
users.py - manages the Linux accounts that tunnel users authenticate
as. Dropbear (like OpenSSH) authenticates against normal system
accounts, so this is the same useradd/chpasswd/chage approach - no
dropbear-specific user database to manage separately.
"""
import random
import string
from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import List, Optional

from .system import Shell


@dataclass
class SSHUser:
    username: str
    expiry_date: str


class SSHUserManager:
    def __init__(self, shell: Shell = Shell):
        self.shell = shell

    @staticmethod
    def _random_password(length: int = 10) -> str:
        alphabet = string.ascii_letters + string.digits
        return "".join(random.choice(alphabet) for _ in range(length))

    def add_user(self, username: str, days_valid: int = 30, password: Optional[str] = None) -> SSHUser:
        password = password or self._random_password()
        expiry = (datetime.utcnow() + timedelta(days=days_valid)).strftime("%Y-%m-%d")
        self.shell.run(["useradd", "-m", "-s", "/bin/false", "-e", expiry, username])
        self.shell.run(["chpasswd"], input_text=f"{username}:{password}\n")
        print(f"[+] Created user '{username}', expires {expiry}")
        print(f"    password: {password}")
        return SSHUser(username=username, expiry_date=expiry)

    def extend_user(self, username: str, extra_days: int) -> str:
        new_expiry = (datetime.utcnow() + timedelta(days=extra_days)).strftime("%Y-%m-%d")
        self.shell.run(["chage", "-E", new_expiry, username])
        print(f"[+] '{username}' now expires {new_expiry}")
        return new_expiry

    def delete_user(self, username: str):
        self.shell.run(["userdel", "-r", username], check=False)
        print(f"[-] Deleted user '{username}'")

    def lock_user(self, username: str):
        self.shell.run(["usermod", "-L", username])
        print(f"[*] Locked '{username}'")

    def unlock_user(self, username: str):
        self.shell.run(["usermod", "-U", username])
        print(f"[*] Unlocked '{username}'")

    def list_users(self) -> List[SSHUser]:
        users = []
        with open("/etc/passwd") as f:
            for line in f:
                parts = line.strip().split(":")
                if len(parts) < 7:
                    continue
                name, uid = parts[0], parts[2]
                if not uid.isdigit() or int(uid) < 1000 or name == "nobody":
                    continue
                expiry = self._get_expiry(name)
                users.append(SSHUser(username=name, expiry_date=expiry or "never"))
        return users

    def _get_expiry(self, username: str) -> Optional[str]:
        result = self.shell.run(["chage", "-l", username], capture=True, check=False)
        for line in (result.stdout or "").splitlines():
            if "Account expires" in line:
                value = line.split(":", 1)[1].strip()
                return None if value.lower() == "never" else value
        return None
