# 更新 Ghidra 中的函数名称和注释, 以及一些 Label 的名称和注释
# @author
# @category Python 3
# @keybinding
# @menupath
# @toolbar

import os
import sys

from ghidra.program.model.listing import CodeUnit
from ghidra.program.model.symbol import SourceType, SymbolType

currentProgram = getCurrentProgram()
functionManager = currentProgram.getFunctionManager()
listing = currentProgram.getListing()
symbolTable = currentProgram.getSymbolTable()

SCRIPT_DIR = os.path.dirname(os.path.realpath(__file__))

# 引入 misc.py
MISC_PATH = os.path.join(SCRIPT_DIR, "misc.py")
if MISC_PATH not in sys.path:
    sys.path.append(MISC_PATH)

from misc import ALL_FUNCTIONS_FILE, _collect_functions, _write_functions


def update_struct(file_path: str):
    # 读取函数
    functions = _collect_functions(file_path)

    # 更新函数
    for function in functions:
        addr = toAddr(function.address)
        func = functionManager.getFunctionAt(addr)
        if func:
            func.setName(function.name, SourceType.USER_DEFINED)
            func.setComment(function.comment)
            for tag in function.tags:
                func.addTag(tag)
            print(f"Function at 0x{function.address:X} renamed to '{function.name}'")
            continue

        symbol = symbolTable.getPrimarySymbol(addr)
        if symbol and symbol.getSymbolType() == SymbolType.LABEL:
            symbol.setName(function.name, SourceType.USER_DEFINED)
            listing.setComment(addr, CodeUnit.REPEATABLE_COMMENT, function.comment)
            print(f"Symbol at 0x{function.address:X} renamed to '{function.name}'")
            continue

        listing.setComment(addr, CodeUnit.REPEATABLE_COMMENT, function.comment)
        print(f"Function at 0x{function.address:X} not found.")

    # 按地址排序
    functions.sort(key=lambda x: x.address)

    # 保存函数
    _write_functions(functions, file_path)


update_struct(ALL_FUNCTIONS_FILE)
