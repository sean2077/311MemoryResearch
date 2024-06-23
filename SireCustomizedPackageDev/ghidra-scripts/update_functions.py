# TODO write a description for this script
# @author
# @category Python 3
# @keybinding
# @menupath
# @toolbar


import os
from dataclasses import dataclass

from ghidra.program.model.listing import CodeUnit
from ghidra.program.model.symbol import SourceType
from java.io import File
from javax.swing import JFileChooser

currentProgram = getCurrentProgram()
functionManager = currentProgram.getFunctionManager()
listing = currentProgram.getListing()


def choose_files():
    # 获取脚本所在目录
    script_dir = os.path.dirname(os.path.abspath(__file__))

    # 创建一个文件选择器
    file_chooser = JFileChooser()

    # 设置文件选择模式，可以是 FILES_ONLY, DIRECTORIES_ONLY, FILES_AND_DIRECTORIES
    file_chooser.setFileSelectionMode(JFileChooser.FILES_ONLY)

    # 启用多选模式
    file_chooser.setMultiSelectionEnabled(True)

    # 设置初始目录为脚本所在目录
    file_chooser.setCurrentDirectory(File(script_dir))

    # 显示打开文件对话框
    result = file_chooser.showOpenDialog(None)

    # 如果用户选择了一个或多个文件
    if result == JFileChooser.APPROVE_OPTION:
        selected_files = file_chooser.getSelectedFiles()
        file_paths = [file.getAbsolutePath() for file in selected_files]
        print("Selected files:")
        for file_path in file_paths:
            print(file_path)
        return file_paths
    else:
        print("File selection canceled.")
        return []


def clean_name(name: str) -> str:
    # 去掉 name 中不能作为名称的字符
    # fmt: off
    illegal_chars = [" "]
    # fmt: on
    for char in illegal_chars:
        name = name.replace(char, "_")

    return name


@dataclass
class Function:
    address: int
    name: str
    comment: str

    @classmethod
    def from_table_row(cls, row):
        items = row.strip().strip("|").split("|")
        if len(items) != 3:
            raise ValueError(f"Invalid row: {row}")
        address, name, comment = items
        address = int(address, 16)
        name = clean_name(name.strip())
        comment = f"{name}. {comment.strip()}"
        return cls(address, name, comment)


def handle(file_path: str):
    functions = []
    reach_functions = False
    with open(file_path, "r", encoding="utf-8") as f:
        for line in f:
            if not line.strip():
                continue
            if not reach_functions and line.startswith("| --------"):
                reach_functions = True
                continue
            if reach_functions:
                functions.append(Function.from_table_row(line))

    for function in functions:
        func = functionManager.getFunctionAt(toAddr(function.address))
        if func:
            func.setName(function.name, SourceType.USER_DEFINED)
            func.setComment(function.comment)
            print(f"Updating function at 0x{function.address:X} to '{function.name}'")
        else:
            print(f"Function at 0x{function.address:X} not found.")
            # 在此处添加comment
            listing.setComment(toAddr(function.address), CodeUnit.REPEATABLE_COMMENT, function.comment)


def main():
    file_paths = choose_files()
    for file_path in file_paths:
        print("processing file:", file_path)
        handle(file_path)
        print("-" * 50)


main()
