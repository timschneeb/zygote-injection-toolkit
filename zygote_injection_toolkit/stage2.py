import socket
import codecs
import re
import shlex
from typing import Any
from io import BytesIO
from warnings import warn
from pathlib import Path

import aidl

from zygote_injection_toolkit.exceptions import *
from zygote_injection_toolkit.parcel import *


def swap_endianness(bytes_: bytes) -> bytes:
    result = b""
    bytes_io = BytesIO(bytes_)
    while True:
        read_bytes = bytes_io.read(4)
        if not read_bytes:
            break
        result += read_bytes[::-1]
    return result


# https://stackoverflow.com/a/53198696


def parse_service_result(service_result: str) -> bytes:
    'decodes the raw response from the "service call" AOSP command line utility'
    EXPRESSION = re.compile(
        r"^(?:Result\: Parcel\(|  0x[0-9a-fA-F]+: )((?:[0-9a-fA-F ])+)'[^']*'\)?$"
    )

    matched_any = False
    result = b""
    for line in service_result.split("\n"):
        matched = EXPRESSION.fullmatch(line)
        if matched is None:
            continue
        matched_any = True
        result += codecs.decode(matched[1].replace(" ", ""), "hex")
    # print(swap_endianness(result)[4:].decode("utf-16le"))
    if not matched_any:
        raise ZygoteInjectionException("service call failed")
    return swap_endianness(result)


# aosp/frameworks/base/core/java/android/service/oemlock/IOemLockService.aidl
# 0 = String getLockName();
# 1 = void setOemUnlockAllowedByCarrier(boolean allowed, in byte[] signature);
# 2 = boolean isOemUnlockAllowedByCarrier();
# 3 = void setOemUnlockAllowedByUser(boolean allowed);
# 4 = boolean isOemUnlockAllowedByUser();
# 5 = boolean isOemUnlockAllowed();
# 6 = boolean isDeviceOemUnlocked();


def parse_boolean_result(result: bytes) -> bool:
    status_code = int.from_bytes(result[:4], "little")
    if status_code:
        raise Exception("oh no!")
    number = int.from_bytes(result[4:8], "little")
    return bool(number)


with open(Path(__file__).parent / "IOemLockService.aidl") as handle:
    oem_lock_service_aidl = handle.read()
oem_lock_service = parse_aidl_interface(
    aidl.fromstring(oem_lock_service_aidl), "IOemLockService"
)
known_services = {"oem_lock": oem_lock_service}


class Stage2Exploit:
    def __init__(self, port: int = 1234) -> None:
        self.port = port

    def call_service(
        self,
        device_socket: socket.SocketType,
        service_name: str,
        function: str,
        *arguments: ParcelType
    ) -> ...:
        interface = known_services[service_name]
        service_function = interface[function]
        parsed_arguments = service_function.parse_arguments(arguments)

        command_parameters = [
            "service",
            "call",
            service_name,
            str(service_function.code),
            *parsed_arguments,
        ]
        command = shlex.join(command_parameters) + "\n"
        device_socket.sendall(command.encode("utf-8"))
        service_result = device_socket.recv(10000).decode("utf-8")

        return_value = parse_service_result(service_result)
        # add an int32 for the status code
        parsed_return_value = service_function.parse_return(return_value)
        status_code = parsed_return_value[0]

        formatted_arguments = ", ".join(repr(argument) for argument in arguments)
        formatted_service_call = f"{function}({formatted_arguments})"
        if status_code:
            raise ZygoteInjectionException(
                f"service call {formatted_service_call} returned error {status_code:d}"
            )
        if parsed_return_value[1:]:
            print(
                f"service call {formatted_service_call} = {repr(parsed_return_value[1])}"
            )
        else:
            print(f"service call {formatted_service_call}")
        try:
            return parsed_return_value[1]
        except IndexError:
            return None

    def exploit_stage2(self):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as device_socket:
            device_socket.connect(("127.0.0.1", self.port))
            # in case there is already a partially typed command
            device_socket.sendall(b"\n")

            allowed_by_carrier = self.call_service(
                device_socket, "oem_lock", "isOemUnlockAllowedByCarrier"
            )
            oem_unlock_allowed = self.call_service(
                device_socket, "oem_lock", "isOemUnlockAllowed"
            )
            if not allowed_by_carrier:
                print(
                    "OEM unlock is blocked by carrier, attempting to remove carrier lock"
                )
                self.call_service(
                    device_socket, "oem_lock", "setOemUnlockAllowedByCarrier", 1
                )
                # verify that the unlock worked
                if self.call_service(
                    device_socket, "oem_lock", "isOemUnlockAllowedByCarrier"
                ):
                    message = "CARRIER OEM UNLOCK BYPASSED"
                    print("*" * (len(message) + 4))
                    print(f"* {message} *")
                    print("*" * (len(message) + 4))
                    print("This means you MIGHT be able to root your device!")
                    print(
                        'Enable OEM unlock in settings and attempt to unlock the bootloader via "fastboot oem unlock"'
                    )
                    print("This may or may not work depending on your device model")
                else:
                    print("Could not bypass carrier OEM unlock")
            if not self.call_service(
                device_socket, "oem_lock", "isOemUnlockAllowedByUser"
            ):
                self.call_service(
                    device_socket, "oem_lock", "setOemUnlockAllowedByUser", 1
                )
                if not self.call_service(
                    device_socket, "oem_lock", "isOemUnlockAllowedByUser"
                ):
                    print(
                        "Could not change user OEM unlock, please enable it in developer options"
                    )
            if not oem_unlock_allowed and self.call_service(
                device_socket, "oem_lock", "isOemUnlockAllowed"
            ):
                print("OEM unlock is now allowed!")
            if self.call_service(device_socket, "oem_lock", "isDeviceOemUnlocked"):
                print(
                    'Your bootloader seems to be unlocked, try running "fastboot flashing ..."'
                )


# Stage2Exploit().exploit_stage2()
# exit()
