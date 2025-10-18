import shlex
from enum import Enum
from typing import Optional, Union
from ppadb.client import Client as AdbClient

from zygote_injection_toolkit.exceptions import *

PropValue = Union[str, int, float, bool]

class ConnectResult(Enum):
    success = 0
    success_specific_device = 1  # connected to the explicitly specified device
    failed_multiple_devices = 2
    failed_no_devices = 3
    failed_specific_device = 4  # could not find the device

    @property
    def succeeded(self) -> bool:
        return self.value in (self.success, self.success_specific_device)

class Device:
    def __init__(
            self,
            device_serial: Optional[str] = None,
            auto_connect: bool = True,
            adb_client: Optional[AdbClient] = None
    ) -> None:
        self.adb = None
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
        self.adb = device
    
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
    
        result = self.adb.shell_v2(
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
