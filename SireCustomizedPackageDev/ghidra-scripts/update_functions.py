# 更新 Ghidra 中的函数名称和注释
# @author
# @category Python 3
# @keybinding
# @menupath
# @toolbar

import os
import sys

from ghidra.program.model.listing import CodeUnit
from ghidra.program.model.symbol import SourceType

currentProgram = getCurrentProgram()
functionManager = currentProgram.getFunctionManager()
listing = currentProgram.getListing()

SCRIPT_DIR = os.path.dirname(os.path.realpath(__file__))

# 引入 misc.py
MISC_PATH = os.path.join(SCRIPT_DIR, "misc.py")
if MISC_PATH not in sys.path:
    sys.path.append(MISC_PATH)

from misc import ALL_FUNCTIONS_FILE, _collect_functions


def update_struct(file_path: str):
    # 读取函数
    functions = _collect_functions(file_path)

    # 更新函数
    for function in functions:
        func = functionManager.getFunctionAt(toAddr(function.address))
        if func:
            func.setName(function.name, SourceType.USER_DEFINED)
            func.setComment(function.comment)
            print(f"Function at 0x{function.address:X} renamed to '{function.name}'")
        else:
            print(f"Function at 0x{function.address:X} not found.")
            # 在此处添加comment
            listing.setComment(toAddr(function.address), CodeUnit.REPEATABLE_COMMENT, function.comment)


update_struct(ALL_FUNCTIONS_FILE)
