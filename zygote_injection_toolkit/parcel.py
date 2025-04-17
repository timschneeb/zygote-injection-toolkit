"parser for raw Android Parcels"
import aidl
from types import NoneType
from typing import Optional, Any

# https://foundryzero.co.uk/2022/11/14/binder-tracing-part-2.html
# https://android.googlesource.com/platform/frameworks/base/+/pie-release/wifi/java/android/net/wifi/IWifiManager.aidl


class ParcelType:
    def length(self) -> Optional[int]:
        "gets the length of this type, or None the size is not fixed"
        return None

    def _decode_variable(self, data: bytes) -> tuple[int, Any]:
        length = self.length
        if length is None:
            raise ValueError(
                "cannot decode a type of variable length without variable decode method"
            )
        else:
            return length, self._decode_fixed(data[:length])

    def _decode_fixed(self, data: bytes) -> Any:
        raise ValueError("cannot decode a fixed value")

    def decode(self, data: bytes) -> tuple[bytes, Any]:
        "read from a parcel and return the leftover bytes"
        length, value = self._decode_variable(data)
        if length > len(data):
            raise ValueError("not enough data to parse")
        return data[length:], value

    def encode(self, value: Any) -> list[str]:
        raise ValueError("this type cannot be encoded")


class ParcelVoid(ParcelType):
    @property
    def length(self) -> int:
        return 0

    def _decode_fixed(self, data: bytes) -> None:
        return None

    def encode(self, value: NoneType) -> list[str]:
        return []


class ParcelInt32(ParcelType):
    @property
    def length(self) -> int:
        return 4

    def _decode_fixed(self, data: bytes) -> int:
        return int.from_bytes(data, "little")

    def encode(self, value: int) -> list[str]:
        return ["i32", f"{value:d}"]


class ParcelInt64(ParcelType):
    @property
    def length(self) -> int:
        return 8

    def _decode_fixed(self, data: bytes) -> int:
        return int.from_bytes(data, "little")

    def encode(self, value: int) -> list[str]:
        return ["i64", f"{value:d}"]


class ParcelBool(ParcelType):
    @property
    def length(self) -> int:
        return 4

    def _decode_fixed(self, data: bytes) -> bool:
        return bool(int.from_bytes(data))

    def encode(self, value: bool) -> list[str]:
        return ["i32", f"{value:d}"]


class ParcelString(ParcelType):
    def _decode_variable(self, data: bytes) -> tuple[int, str]:
        print(data)
        string_length = data[0]
        string = data[1 : string_length - 1].decode()
        return string_length + 1, string

    def encode(self, value: str) -> tuple[str]:
        return ["s16", value]


SchemaType = list[ParcelType]


class ServiceFunction:
    "a function on an Android service"

    def __init__(
        self,
        code: int,
        schema: Optional[SchemaType],
        return_type: Optional[ParcelType],
        name: Optional[str] = None,
    ) -> None:
        self.code = code
        self.schema = schema
        self.return_type = return_type
        self.name = name

    @property
    def can_parse(self) -> bool:
        return self.schema is not None and self.return_type is not None

    def parse_arguments(self, arguments: list[Any]) -> list[str]:
        if self.schema is None:
            raise ValueError("cannot parse unknown argument types")
        if len(self.schema) != len(arguments):
            raise ValueError(
                f"service function takes {len(self.schema):d} arguments but {len(arguments)} {"was" if len(arguments) == 1 else "were"} given"
            )
        encoded_arguments = []
        for argument_type, value in zip(self.schema, arguments):
            if not issubclass(argument_type, ParcelVoid):
                encoded_arguments.extend(argument_type().encode(value))
        return encoded_arguments

    def parse_return(self, data: bytes) -> list[int, Any]:
        if self.return_type is None:
            raise ValueError("cannot parse unknown return type")
        return_schema = [ParcelInt32]
        if not issubclass(self.return_type, ParcelVoid):
            return_schema.append(self.return_type)
        return parse_parcel_raw(data, return_schema)


InterfaceType = dict[str, ServiceFunction]


def parse_parcel_raw(data: bytes, signature: SchemaType) -> list:
    result = []
    for parcel_type in signature:
        data, value = parcel_type().decode(data)
        result.append(value)
    return result


def parse_aidl_type(aidl_type: aidl.tree.Type) -> Optional[ParcelType]:
    if aidl_type is None:
        return ParcelVoid
    BASIC_TYPES = {
        "int": ParcelInt32,
        "long": ParcelInt64,
        "boolean": ParcelBool,
        "float": ...,
        "double": ...,
    }
    # a lot of confusing code that takes the type object that aidl-parser generates and turns it into a ParcelType
    if aidl_type.dimensions:
        pass
    elif isinstance(aidl_type, aidl.tree.BasicType):
        try:
            return BASIC_TYPES[aidl_type.name]
        except KeyError:
            pass
    elif isinstance(aidl_type, aidl.tree.ReferenceType):
        if aidl_type.name == "String":
            return ParcelString

    # hack: ignore byte[] so an OEM unlock function can work
    if (
        isinstance(aidl_type, aidl.tree.BasicType)
        and aidl_type.name == "byte"
        and aidl_type.dimensions == [None]
    ):
        return ParcelVoid


def generate_schema(aidl_function: aidl.ast.Node) -> tuple[ParcelType, SchemaType]:
    schema = []
    for parameter in aidl_function.parameters:
        parameter_type = parse_aidl_type(parameter.type)
        if parameter_type is None:
            # if a parameter is unknown, the schema cannot be generated
            schema = None
            break
        elif not issubclass(parameter_type, ParcelVoid):
            schema.append(parameter_type)
    return schema, parse_aidl_type(aidl_function.return_type)


def parse_aidl_interface(
    aidl_definition: aidl.ast.Node, interface_name: str
) -> InterfaceType:
    for type_ in aidl_definition.types:
        if type_.name == interface_name:
            aidl_interface = type_
            break
    else:
        raise KeyError("interface not found")

    result = {}
    for function, code in zip(aidl_interface.body, range(len(aidl_interface.body))):
        schema, return_type = generate_schema(function)
        result[function.name] = ServiceFunction(
            code, schema, return_type, function.name
        )
    return result
