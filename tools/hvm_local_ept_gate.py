"""每处理器私有 EPT 的静态门禁。

这个改动动的是 VM-exit 路径，而那条路径没有任何运行期验证手段：加载驱动要
测试签名，宿主机不能当靶机。所以能在编译机上钉死的不变量必须钉死。

门禁只查两条，都是"少一个字就会静默退化成共享层次"的地方：

1. 翻转路径上的 INVEPT 操作数必须是 transient 里那个，不能直接用共享指针。
   写成操作数白名单而不是"禁止出现 Runtime->EptPointer"——后者会误伤同一
   文件里合法的引用，而且加一个空格就绕过去了。

2. 两个 arm 站点必须仍然接收 Local 参数。签名被改回去而调用点还能编译的
   情况是存在的（参数可以被静默丢弃），所以这里直接比对签名文本。
"""

import re
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
HVM = REPO / "KswordARKDriver" / "src" / "features" / "hvm"

# 翻转路径上允许的 INVEPT 操作数：必须优先用 transient 记录的那个层次。
ALLOWED_OPERAND = re.compile(
    r"Transient->EptPointer\s*!=\s*0ULL\s*\?\s*"
    r"Transient->EptPointer\s*:\s*Runtime->EptPointer",
    re.S,
)

# 私有根首次使用前的失效是另一处合法用法，操作数是 EptLocal 自己的指针。
ALLOWED_PRIVATE_ROOT = re.compile(r"Context->EptLocal->EptPointer", re.S)

INVEPT_CALL = re.compile(r"KswordARKHvmAsmInveptSingle\s*\(([^;]*?)\)\s*", re.S)

# 只查翻转路径的函数体。安装与卸载也调 INVEPT，但它们跑在 PASSIVE 且在常驻
# 期间被拒绝，改的是共享叶项——那里用共享指针是对的。把它们算进来会让门禁
# 变成误报源，而一个会误报的门禁迟早会被关掉，那比没有门禁更糟。
FLIP_FUNCTIONS = [
    ("hvm_ept.c", "KswordARKHvmEptRestoreTransient"),
    ("hvm_ept.c", "KswordARKHvmEptHandleViolation"),
    ("hvm_ept_view.c", "KswordARKHvmEptViewHandleViolation"),
    ("hvm_resident.c", "KswordARKHvmConfigureResidentVmcsFromAsm"),
]

REQUIRED_SIGNATURES = [
    ("hvm_ept.c", "KswordARKHvmEptHandleViolation"),
    ("hvm_ept.h", "KswordARKHvmEptHandleViolation"),
    ("hvm_ept_view.c", "KswordARKHvmEptViewHandleViolation"),
    ("hvm_ept_view.h", "KswordARKHvmEptViewHandleViolation"),
]

NEWLINE = chr(10)


def function_bodies(text, symbol):
    """取一个顶层函数的每个函数体，连同它在文件里的偏移。

    C 源码里函数结束的右大括号在第 0 列，这个约定在本仓库是稳定的，比配对
    大括号简单得多，也不会被字符串或注释里的括号骗到。
    """
    bodies = []
    marker = NEWLINE + symbol + "("
    start = text.find(marker)
    while start != -1:
        opening = text.find(NEWLINE + "{", start)
        if opening == -1:
            break
        end = text.find(NEWLINE + "}", opening)
        if end == -1:
            break
        bodies.append((opening, text[opening:end]))
        start = text.find(marker, end)
    return bodies


def check_invept_operands():
    """每一个翻转路径上的 INVEPT 都必须命名正确的层次。"""
    failures = []
    for name, symbol in FLIP_FUNCTIONS:
        text = (HVM / name).read_text(encoding="utf-8")
        bodies = function_bodies(text, symbol)
        if not bodies:
            failures.append("{}: 找不到 {} 的函数体".format(name, symbol))
            continue
        for offset, body in bodies:
            for match in INVEPT_CALL.finditer(body):
                operand = match.group(1)
                if ALLOWED_OPERAND.search(operand):
                    continue
                if ALLOWED_PRIVATE_ROOT.search(operand):
                    continue
                line = text[: offset + match.start()].count(NEWLINE) + 1
                failures.append(
                    "{}:{} {} 里的 INVEPT 操作数不在白名单内：{}".format(
                        name, line, symbol, " ".join(operand.split())
                    )
                )
    return failures


def check_arm_site_signatures():
    """两个 arm 站点必须仍然接收 Local 描述符。"""
    failures = []
    for name, symbol in REQUIRED_SIGNATURES:
        text = (HVM / name).read_text(encoding="utf-8")
        found = False
        index = text.find(symbol + "(")
        while index != -1:
            end = text.find(")", index)
            if end != -1 and "_In_opt_ const KSW_HVM_EPT_LOCAL* Local" in text[index:end]:
                found = True
                break
            index = text.find(symbol + "(", index + 1)
        if not found:
            failures.append(
                "{}: {} 的签名里没有 Local 参数，私有层次会被静默绕过".format(
                    name, symbol
                )
            )
    return failures


def main():
    failures = check_invept_operands() + check_arm_site_signatures()
    if failures:
        sys.stdout.write("每处理器私有 EPT 门禁失败：" + NEWLINE)
        for failure in failures:
            sys.stdout.write("  - {}".format(failure) + NEWLINE)
        return 1
    sys.stdout.write("每处理器私有 EPT 门禁通过。" + NEWLINE)
    return 0


if __name__ == "__main__":
    sys.exit(main())
