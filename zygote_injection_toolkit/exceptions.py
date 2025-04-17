class ZygoteInjectionException(Exception):
    pass


class ZygoteInjectionNotVulnerableException(ZygoteInjectionException):
    "The device is not vulnerable due to the installing the 2024-06-01 security patch"


class ZygoteInjectionCommandFailedException(ZygoteInjectionException):
    "A shell command failed with an exit code"


class ZygoteInjectionConnectException(ZygoteInjectionException):
    "An error occurred trying to connect to a device"


class ZygoteInjectionNoDeviceException(ZygoteInjectionConnectException):
    pass


class ZygoteInjectionMultipleDevicesException(ZygoteInjectionConnectException):
    pass


class ZygoteInjectionDeviceNotFoundException(ZygoteInjectionConnectException):
    "A specific seriral number was passed but the device was not found"


__all__ = [
    "ZygoteInjectionException",
    "ZygoteInjectionNotVulnerableException",
    "ZygoteInjectionCommandFailedException",
    "ZygoteInjectionConnectException",
    "ZygoteInjectionNoDeviceException",
    "ZygoteInjectionMultipleDevicesException",
    "ZygoteInjectionDeviceNotFoundException",
]
