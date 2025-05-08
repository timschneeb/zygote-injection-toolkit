"a utility to search AOSP SELinux rules in order to try to figure out a way to get a particular context"
import re
from typing import Optional
from pathlib import Path

# Equivalent to the LEVELFROM_ enums in C
LEVELFROM_NONE = "none"
LEVELFROM_APP = "app"
LEVELFROM_USER = "user"
LEVELFROM_ALL = "all"

# find / -name seapp_contexts -o -name plat_seapp_contexts -o -name product_seapp_contexts -o -name vendor_seapp_contexts -o -name nonplat_seapp_contexts -o -name odm_seapp_contexts 2> /dev/null
SEAPP_PATHS = [
    "/system/etc/selinux/plat_seapp_contexts",
    "/plat_seapp_contexts",
    "/product/etc/selinux/product_seapp_contexts",
    "/product_seapp_contexts",
    "/vendor/etc/selinux/vendor_seapp_contexts",
    "/vendor_seapp_contexts",
    "/vendor/etc/selinux/nonplat_seapp_contexts",
    "/nonplat_seapp_contexts",
    "/odm/etc/selinux/odm_seapp_contexts",
    "/odm_seapp_contexts",
]


# Mock function for get_minTargetSdkVersion - assume it converts to int
def get_minTargetSdkVersion(value_str):
    """Mocks the C get_minTargetSdkVersion function."""
    try:
        version = int(value_str)
        # C code checks for < 0
        if version < 0:
            return -1  # Indicate error like C
        return version
    except ValueError:
        return -1  # Indicate error


# I used an LLM to generate this because I don't want to deal with the complicated logic in
# external/selinux/libselinux/src/android/android_platform.c selinux_android_seapp_context_reload
def parse_seapp_line(line):
    """
    Parses a single line from a seapp_contexts file based on the provided C logic.

    Args:
        line: The string representing one line from the file.

    Returns:
        A dictionary containing the parsed attributes if the line is valid,
        None if the line is a comment, blank, or contains a parsing error.
    """
    # 1. Read line, get length (Python handles length implicitly)
    # 2. Check for line containing NUL byte as first entry (Python strings don't have NUL like C char arrays,
    #    an empty string after strip is the closest equivalent we need to handle).
    # 3. Remove trailing newline (strip handles this)
    # 4. Skip leading whitespace (strip handles this)
    p = line.strip()

    # 5. If starts with '#' or is empty, continue (return None)
    if not p or p.startswith("#"):
        return None

    # 6. Initialize a structure (dictionary) for the parsed context
    #    Initialize fields similar to calloc(1, sizeof(struct seapp_context)) - mostly zero/false/None
    cur = {
        "isSystemServer": False,
        "isEphemeralAppSet": False,
        "isEphemeralApp": False,
        "isV2AppSet": False,
        "isV2App": False,
        "isOwnerSet": False,
        "isOwner": False,
        # String fields structured like C's String sepol_string type (str, len, is_prefix)
        "user": {"str": None, "is_prefix": False},
        "seinfo": None,
        "name": {"str": None, "is_prefix": False},
        "domain": None,
        "type": None,
        "levelFrom": None,  # Stores LEVELFROM_* string
        "level": None,
        "path": {"str": None, "is_prefix": False},
        "isPrivAppSet": False,
        "isPrivApp": False,
        "minTargetSdkVersion": -1,  # C initializes this to 0, but checks for < 0 return
        "fromRunAs": False,
    }

    # 7. Split the line into tokens using space or tab as delimiters (strtok_r logic)
    tokens = re.split(r"[ \t]+", p)

    # 8. Process each token (while(1) loop in C)
    for token in tokens:
        # Find the '='
        eq_pos = token.find("=")
        if eq_pos == -1:
            # Token doesn't contain '=', goto err
            return None

        # Split into name and value
        name = token[:eq_pos]
        value = token[eq_pos + 1 :]

        # Process based on name (strcasecmp logic)
        name_lower = name.lower()

        # Helper for parsing booleans
        def parse_bool(val_str):
            if val_str.lower() == "true":
                return True
            elif val_str.lower() == "false":
                return False
            else:
                return None  # Indicates parse error

        # Helper for parsing strings with optional '*' prefix flag
        def parse_string_with_prefix(val_str):
            is_prefix = False
            if val_str.endswith("*"):
                is_prefix = True
                val_str = val_str[:-1]  # Store string without '*'
            return {"str": val_str, "is_prefix": is_prefix}

        if name_lower == "issystemserver":
            b_val = parse_bool(value)
            if b_val is None:
                return None  # goto err
            cur["isSystemServer"] = b_val
        elif name_lower == "isephemeralapp":
            cur["isEphemeralAppSet"] = True
            b_val = parse_bool(value)
            if b_val is None:
                return None  # goto err
            cur["isEphemeralApp"] = b_val
        elif name_lower == "isv2app":
            cur["isV2AppSet"] = True
            b_val = parse_bool(value)
            if b_val is None:
                return None  # goto err
            cur["isV2App"] = b_val
        elif name_lower == "isowner":
            cur["isOwnerSet"] = True
            b_val = parse_bool(value)
            if b_val is None:
                return None  # goto err
            cur["isOwner"] = b_val
        elif name_lower == "user":
            if cur["user"]["str"] is not None:
                return None  # goto err (already set)
            cur["user"] = parse_string_with_prefix(value)
        elif name_lower == "seinfo":
            if cur["seinfo"] is not None:
                return None  # goto err (already set)
            if ":" in value:
                return None  # goto err (seinfo cannot contain ':')
            cur["seinfo"] = value
        elif name_lower == "name":
            if cur["name"]["str"] is not None:
                return None  # goto err (already set)
            cur["name"] = parse_string_with_prefix(value)
        elif name_lower == "domain":
            if cur["domain"] is not None:
                return None  # goto err (already set)
            cur["domain"] = value
        elif name_lower == "type":
            if cur["type"] is not None:
                return None  # goto err (already set)
            cur["type"] = value
        elif name_lower == "levelfromuid":
            if cur["levelFrom"] is not None:
                return None  # goto err (already set)
            if value.lower() == "true":
                cur["levelFrom"] = LEVELFROM_APP
            elif value.lower() == "false":
                cur["levelFrom"] = LEVELFROM_NONE
            else:
                return None  # goto err
        elif name_lower == "levelfrom":
            if cur["levelFrom"] is not None:
                return None  # goto err (already set)
            if value.lower() == "none":
                cur["levelFrom"] = LEVELFROM_NONE
            elif value.lower() == "app":
                cur["levelFrom"] = LEVELFROM_APP
            elif value.lower() == "user":
                cur["levelFrom"] = LEVELFROM_USER
            elif value.lower() == "all":
                cur["levelFrom"] = LEVELFROM_ALL
            else:
                return None  # goto err
        elif name_lower == "level":
            if cur["level"] is not None:
                return None  # goto err (already set)
            cur["level"] = value
        elif name_lower == "path":
            if cur["path"]["str"] is not None:
                return None  # goto err (already set)
            cur["path"] = parse_string_with_prefix(value)
        elif name_lower == "isprivapp":
            cur["isPrivAppSet"] = True
            b_val = parse_bool(value)
            if b_val is None:
                return None  # goto err
            cur["isPrivApp"] = b_val
        elif name_lower == "mintargetsdkversion":
            cur["minTargetSdkVersion"] = get_minTargetSdkVersion(value)
            if cur["minTargetSdkVersion"] < 0:
                return None  # goto err (invalid version)
        elif name_lower == "fromrunas":
            b_val = parse_bool(value)
            if b_val is None:
                return None  # goto err
            cur["fromRunAs"] = b_val
        else:
            # Unknown name, goto err
            return None

    if cur["name"]["str"] is not None and (
        cur["seinfo"] is None or cur["seinfo"].lower() == "default"
    ):
        # Insecure configuration, goto err
        return None

    return cur


class SELinuxRule:
    def __init__(self, rule: str) -> None:
        self.rule = rule

    @staticmethod
    def parse_token(name: str, value: str) -> None:
        result = {}

        def parse_bool(value: str) -> bool:
            if value.lower() == "true":
                return True
            elif value.lower() == "false":
                return False
            else:
                raise ValueError(f"invalid boolean {repr(value)}")

        def parse_string_with_prefix(val_str):
            is_prefix = False
            if val_str.endswith("*"):
                is_prefix = True
                val_str = val_str[:-1]  # Store string without '*'
            return {"str": val_str, "is_prefix": is_prefix}

        name_lower = name.lower()

        # mess of if statements that parses the different names
        if name_lower == "issystemserver":
            result["isSystemServer"] = parse_bool(value)
        elif name_lower == "isephemeralapp":
            result["isEphemeralAppSet"] = True
            result["isEphemeralApp"] = parse_bool(value)
        elif name_lower == "isv2app":
            result["isV2AppSet"] = True
            result["isV2App"] = parse_bool(value)
        elif name_lower == "isowner":
            result["isOwnerSet"] = True
            result["isOwner"] = parse_bool(value)
        elif name_lower == "user":
            result["user"] = parse_string_with_prefix(value)
        elif name_lower == "seinfo":
            if ":" in value:
                raise ValueError("seinfo cannot contain ':'")
            result["seinfo"] = value
        elif name_lower == "name":
            result["name"] = parse_string_with_prefix(value)
        elif name_lower == "domain":
            result["domain"] = value
        elif name_lower == "type":
            result["type"] = value
        elif name_lower == "levelfromuid":
            value_bool = parse_bool(value)
            if value_bool:
                result["levelFrom"] = LEVELFROM_APP
            else:
                result["levelFrom"] = LEVELFROM_NONE
        elif name_lower == "levelfrom":
            if value.lower() == "none":
                result["levelFrom"] = LEVELFROM_NONE
            elif value.lower() == "app":
                result["levelFrom"] = LEVELFROM_APP
            elif value.lower() == "user":
                result["levelFrom"] = LEVELFROM_USER
            elif value.lower() == "all":
                result["levelFrom"] = LEVELFROM_ALL
            else:
                raise ValueError(f"invalid levelfrom {repr(value)}")
        elif name_lower == "level":
            if result["level"] is not None:
                raise ValueError("already set")
            result["level"] = value
        elif name_lower == "path":
            result["path"] = parse_string_with_prefix(value)
        elif name_lower == "isprivapp":
            result["isPrivAppSet"] = True
            result["isPrivApp"] = parse_bool(value)
        elif name_lower == "mintargetsdkversion":
            version = get_minTargetSdkVersion(value)
            result["minTargetSdkVersion"] = version
            if version < 0:
                raise ValueError(f"invalid version {repr(version)}")
        elif name_lower == "fromrunas":
            result["fromRunAs"] = parse_bool(value)
        else:
            raise ValueError(f"unknown name {repr(name)}")

        return result

    @classmethod
    def parse_rule(cls, rule: str) -> Optional[dict]:
        result = {
            "isSystemServer": False,
            "isEphemeralAppSet": False,
            "isEphemeralApp": False,
            "isV2AppSet": False,
            "isV2App": False,
            "isOwnerSet": False,
            "isOwner": False,
            "user": {"str": None, "is_prefix": False},
            "seinfo": None,
            "name": {"str": None, "is_prefix": False},
            "domain": None,
            "type": None,
            "levelFrom": None,
            "level": None,
            "path": {"str": None, "is_prefix": False},
            "isPrivAppSet": False,
            "isPrivApp": False,
            "minTargetSdkVersion": 0,
            "fromRunAs": False,
        }
        try:
            comment_index = rule.index("#")
        except ValueError:
            rule_without_comment = rule
        else:
            rule_without_comment = rule[:comment_index]
        if not rule_without_comment:
            return None
        tokens = re.split(r"[ \t]+", rule_without_comment.strip())

        for token in tokens:
            try:
                equal_index = token.index("=")
            except ValueError:
                raise ValueError("token missing '='") from None
            name = token[:equal_index]
            value = token[equal_index + 1 :]
            parsed = cls.parse_token(name, value)
            # TODO check properly for duplicates
            result.update(parsed)
        if result["name"]["str"] is not None and (
            result["seinfo"] is None or result["seinfo"].lower() == "default"
        ):
            raise ValueError("invalid configuration")

    @property
    def filler() -> bool:
        return self.parsed is None

    @property
    def rule(self) -> str:
        return self.__rule

    @rule.setter
    def rule(self, value: str) -> None:
        self.__rule = value
        self.parsed = self.parse_rule(value)


def search(files: list[Path]) -> None:
    # not in the repo yet, specific to each phone
    with open(Path(__file__).parent / "selinuxrules.txt") as selinux_rules_in:
        selinux_rules = selinux_rules_in.read()
    for rule in selinux_rules.split("\n"):
        rule = SELinuxRule(rule)
        print(rule)


def main() -> None:
    search(...)


if __name__ == "__main__":
    main()
