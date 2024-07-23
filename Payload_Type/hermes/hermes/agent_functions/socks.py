from mythic_container.MythicCommandBase import *
from mythic_container.MythicRPC import *


class SocksArguments(TaskArguments):
    def __init__(self, command_line, **kwargs):
        super().__init__(command_line, **kwargs)
        self.args = [
            CommandParameter(
                name="action",
                type=ParameterType.ChooseOne,
                description="Start or Stop socks through this callback",
                choices=["start","stop","flush"]
            ),
            CommandParameter(
                name="port",
                type=ParameterType.Number,
                description="Port number on Mythic server to open for socksv5",
            ),
        ]

    async def parse_arguments(self):
        pass

class SocksCommand(CommandBase):
    cmd = "socks"
    needs_admin = False
    help_cmd = "socks <port>"
    description = "start or stop socks."
    version = 1
    author = "@alalith"
    argument_class = SocksArguments
    attackmapping = ["T1090"]
    attributes = CommandAttributes(
        load_only=False,
        builtin=False
    )

    async def create_go_tasking(self, taskData: PTTaskMessageAllData) -> PTTaskCreateTaskingMessageResponse:
        response = PTTaskCreateTaskingMessageResponse(
            TaskID=taskData.Task.ID,
            Success=True,
        )
        resp = await SendMythicRPCProxyStartCommand(MythicRPCProxyStartMessage(
            TaskID=taskData.Task.ID,
            PortType="socks",
            LocalPort=taskData.args.get_arg("port")
        ))

        if not resp.Success:
            response.TaskStatus = MythicStatus.Error
            response.Stderr = resp.Error
            await SendMythicRPCResponseCreate(MythicRPCResponseCreateMessage(
                TaskID=taskData.Task.ID,
                Response=resp.Error.encode()
            ))
        else:
            response.DisplayParams = "Started SOCKS5 server on port {}".format(taskData.args.get_arg("port"))
            response.TaskStatus = MythicStatus.Success
            response.Completed = True
        return response
    async def process_response(self, task: PTTaskMessageAllData, response: any) -> PTTaskProcessResponseMessageResponse:
        resp = PTTaskProcessResponseMessageResponse(TaskID=task.Task.ID, Success=True)
        return resp
