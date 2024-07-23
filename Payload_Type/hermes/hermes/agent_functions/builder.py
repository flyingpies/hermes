from mythic_container.PayloadBuilder import *
from mythic_container.MythicCommandBase import *
import asyncio
import os
from os import path
from distutils.dir_util import copy_tree
import shutil
import sys
import traceback
import tempfile
import fileinput
import subprocess
import json

# define your payload type class here, it must extend the PayloadType class though
class Hermes(PayloadType):
    name = "hermes"  # name that would show up in the UI
    file_extension = ""  # default file extension to use when creating payloads
    author = "@slyd0g"  # author of the payload type
    supported_os = [SupportedOS.MacOS]  # supported OS and architecture combos
    wrapper = False  # does this payload type act as a wrapper for another payloads inside of it?
    wrapped_payloads = []  # if so, which payload types. If you are writing a wrapper, you will need to modify this variable (adding in your wrapper's name) in the builder.py of each payload that you want to utilize your wrapper.
    note = """A Swift 5 implant targeting macOS"""
    supports_dynamic_loading = False  # setting this to True allows users to only select a subset of commands when generating a payload
    build_parameters = [
        #  these are all the build parameters that will be presented to the user when creating your payload
        BuildParameter(
            name="version",
            parameter_type=BuildParameterType.ChooseOne,
            description="Choose a target macOS version (Catalina, Big Sur and above)",
            choices=["10.15", "11"],
        ),
        BuildParameter(
            name="architecture",
            parameter_type=BuildParameterType.ChooseOne,
            description="Choose a target architecture",
            choices=["x86_64", "arm64", "universal"],
        ),
    ]
    #  the names of the c2 profiles that your agent supports
    c2_profiles = ["http","slack"]


    agent_path = pathlib.Path(".") / "hermes" / "mythic"
    agent_icon_path = agent_path / "hermes.svg"
    agent_code_path = pathlib.Path(".") / "hermes" / "agent_code"

    support_browser_scripts = [
        BrowserScript(script_name="create_table", author="@its_a_feature_")
    ]
    # after your class has been instantiated by the mythic_service in this docker container and all required build parameters have values
    # then this function is called to actually build the payload
    async def build(self) -> BuildResponse:
        # this function gets called to create an instance of your payload
        resp = BuildResponse(status=BuildStatus.Error)

        # get version parameter from Mythic
        target_version = self.get_parameter("version")
        target_architecture = self.get_parameter("architecture")

        try:
            c2 = self.c2info[0]
            profile = c2.get_c2profile()["name"]

            # Copy backup config to config.swift, open it for reading, read data
            agent_config_bak_path = "/Mythic/hermes/agent_code/Hermes/config-{profile}.swift.bak".format(profile=profile)
            agent_config_path = "/Mythic/hermes/agent_code/Hermes/config-{profile}.swift".format(profile=profile)
            shutil.copyfile(agent_config_bak_path, agent_config_path)
            config_file = open(agent_config_path, "rt")
            data = config_file.read()

            # pull user agent, host header, and custom headers from c2info
            user_agent = ""
            host_header = ""
            http_headers = ""
            
            # get c2 profile


            data = data.replace("REPLACE_UUID", self.uuid)
            # parse user agent, host header, and custom headers
            for key, val in c2.get_parameters_dict().items():
                if key == "headers":
                    hl = val
                    for key,value in hl.items():
                        if "User-Agent" in key:
                            user_agent = value
                        elif "Host" in key:
                            host_header = value
                        else:
                            http_headers += f'"{key}"' + ":" + f'"{value}"' + ","#"key1":"value1","key2":"value2"
                if key == "callback_host":
                    use_ssl = "false"
                    if "https" in val:
                            use_ssl = "true"
                    data = data.replace("REPLACE_USE_SSL", use_ssl)
                if key == "killdate":
                    data = data.replace("2099-01-01", value)
                
            for key, val in c2.get_parameters_dict().items():
                if key == "AESPSK":
                    data = data.replace("REPLACE_ENCODED_AES_KEY", val["enc_key"])
                elif key == "callback_host":
                    data = data.replace("REPLACE_CALLBACK_HOST", (val["callback_host"]).replace("https://","").replace("http://",""))
                else:
                    data = data.replace("REPLACE_" +  key.upper(), val) 

            
            # if no extra headers, create empty array in Swift
            if not http_headers:
                http_headers = ":"
            # strip trailing comma out of http_headers
            if http_headers[-1] == ",":
                http_headers = http_headers[:-1]


            # loop through file, replace config
            data = data.replace("REPLACE_USER_AGENT", user_agent)
            data = data.replace("REPLACE_HOST_HEADER", host_header)
            data = data.replace("REPLACE_HTTP_HEADERS", http_headers)


            config_file.close()
             
            # overwrite the input file
            config_file = open(agent_config_path, "wt")
            config_file.write(data)
            config_file.close()

            # trigger different architecture builds here
            if target_architecture == "x86_64" or target_architecture == "arm64":
                # setup build command
                command = 'darling /usr/libexec/darling/bin/bash -c "export SDKROOT=/Library/Developer/CommandLineTools/SDKs/MacOSX.sdk; xcode-select -s /Library/Developer/CommandLineTools; /Library/Developer/CommandLineTools/usr/bin/swiftc -swift-version 5 -import-objc-header Hermes-Bridging-Header.h crypto.swift main.swift helper.swift jobs_manager.swift {profile}.swift config-{profile}.swift commands/* swift_libraries/* -o hermes_{arch}_macosx{version} -target {arch}-apple-macosx{version}"'.format(profile=profile, version=target_version, arch=target_architecture)

                # build Hermes
                proc = await asyncio.create_subprocess_shell(
                    command,
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE,
                    cwd="/Mythic/hermes/agent_code/Hermes/",
                )

                # Collect and data written Standard Output and Standard Error
                stdout, stderr = await proc.communicate()
                if stdout:
                    resp.build_stdout += f"\n[STDOUT]\n{stdout.decode()}"
                if stderr:
                    resp.build_stderr += f"\n[STDERR]\n{stderr.decode()}"

                # get built file
                bin_path = "/Mythic/hermes/agent_code/Hermes/hermes_{arch}_macosx{version}".format(version=target_version, arch=target_architecture)
                if os.path.exists(bin_path):
                    resp.payload = open(bin_path, "rb").read()

                # Successfully created the payload without error
                resp.build_message += f'\nCreated Hermes payload!\n' \
                                    f'OS: {target_version}, ' \
                                    f'Arch: {target_architecture}, ' \
                                    f'C2 Profile: {profile}\n'
                resp.status = BuildStatus.Success
                return resp
            elif target_architecture == "universal":
                # setup build command
                command = 'darling /usr/libexec/darling/bin/bash -c "export SDKROOT=/Library/Developer/CommandLineTools/SDKs/MacOSX.sdk; xcode-select -s /Library/Developer/CommandLineTools; /Library/Developer/CommandLineTools/usr/bin/swiftc -swift-version 5 -import-objc-header Hermes-Bridging-Header.h crypto.swift main.swift helper.swift jobs_manager.swift {profile}.swift config-{profile}.swift commands/* swift_libraries/* -o hermes_x86_64 -target x86_64-apple-macosx{version}"'.format(profile=profile, version=target_version)
                command2 = 'darling /usr/libexec/darling/bin/bash -c "export SDKROOT=/Library/Developer/CommandLineTools/SDKs/MacOSX.sdk; xcode-select -s /Library/Developer/CommandLineTools; /Library/Developer/CommandLineTools/usr/bin/swiftc -swift-version 5 -import-objc-header Hermes-Bridging-Header.h crypto.swift main.swift helper.swift jobs_manager.swift {profile}.swift config-{profile}.swift commands/* swift_libraries/* -o hermes_arm64 -target arm64-apple-macosx{version}"'.format(profile=profile, version=target_version)

                # build Hermes both architecture
                proc = await asyncio.create_subprocess_shell(
                    command,
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE,
                    cwd="/Mythic/hermes/agent_code/Hermes/",
                )

                proc2 = await asyncio.create_subprocess_shell(
                    command2,
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE,
                    cwd="/Mythic/hermes/agent_code/Hermes/",
                )

                # Collect and data written Standard Output and Standard Error
                stdout, stderr = await proc.communicate()
                if stdout:
                    resp.build_stdout += f"\n[STDOUT]\n{stdout.decode()}"
                if stderr:
                    resp.build_stderr += f"\n[STDERR]\n{stderr.decode()}"
                stdout2, stderr2 = await proc2.communicate()
                if stdout2:
                    resp.build_stdout += f"\n[STDOUT]\n{stdout2.decode()}"
                if stderr2:
                    resp.build_stderr += f"\n[STDERR]\n{stderr2.decode()}"

                # Combine Hermes with lipo
                await proc.wait()
                await proc2.wait()
                command3 = 'darling /usr/libexec/darling/bin/bash -c "/Library/Developer/CommandLineTools/usr/bin/lipo -create hermes_x86_64 hermes_arm64 -output hermes_universal_macosx{version}"'.format(version=target_version)
                proc3 = await asyncio.create_subprocess_shell(
                    command3,
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE,
                    cwd="/Mythic/hermes/agent_code/Hermes/",
                )
                stdout3, stderr3 = await proc3.communicate()
                if stdout3:
                    resp.build_stdout += f"\n[STDOUT]\n{stdout3.decode()}"
                if stderr3:
                    resp.build_stderr += f"\n[STDERR]\n{stderr3.decode()}"

                # get built file
                bin_path = "/Mythic/hermes/agent_code/Hermes/hermes_universal_macosx{version}".format(version=target_version)
                if os.path.exists(bin_path):
                    resp.payload = open(bin_path, "rb").read()

                # Successfully created the payload without error
                resp.build_message += f'\nCreated Hermes payload!\n' \
                                    f'OS: {target_version}, ' \
                                    f'Arch: {target_architecture}, ' \
                                    f'C2 Profile: {profile}\n'
                resp.status = BuildStatus.Success
                return resp


        except Exception as e:
            traceback.print_exc()
            resp.build_stderr += "\n" + str(e)
        return resp
