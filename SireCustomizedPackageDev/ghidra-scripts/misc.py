#!python3
"""
杂项任务.

功能：
    - 汇总 functions 目录下函数相关 md 文件 到一个文件中
"""
import os

from attrs import define, field
from typer import Typer

app = Typer()


SCRIPT_DIR = os.path.dirname(os.path.realpath(__file__))
FUNCTIONS_DIR = os.path.join(SCRIPT_DIR, "functions")
DEST_FUNCTIONS_FILE = os.path.join(SCRIPT_DIR, "函数汇总.md")


def clean_name(name: str) -> str:
    # 去掉 name 中不能作为名称的字符
    # fmt: off
    illegal_chars = [" "]
    # fmt: on
    for char in illegal_chars:
        name = name.replace(char, "_")

    return name


@define
class Function:
    address: int
    name: str
    comment: str
    tags: list[str] = field(factory=list)

    @classmethod
    def from_old_table_row(cls, row):  # | 地址 | 函数名 | 注释 |
        items = row.strip().strip("|").split("|")
        if len(items) != 3:
            raise ValueError(f"Invalid row: {row}")
        address, name, comment = items
        address = int(address, 16)
        name = clean_name(name.strip())
        comment = comment.strip()
        return cls(address, name, comment)

    @classmethod
    def from_new_table_row(cls, row):  # |序号| 地址 | 函数名 | 标签 | 注释  |
        items = row.strip().strip("|").split("|")
        if len(items) != 5:
            raise ValueError(f"Invalid row: {row}")

        _, address, name, tags, comment = items
        address = int(address, 16)
        name = clean_name(name.strip())
        tags = tags.strip()
        tags = list(tags.strip().split(",")) if tags else []
        comment = comment.strip()
        return cls(address, name, comment, tags)


def _collect_functions(file_path, dest_functions):
    file_name = os.path.basename(file_path)
    tag = file_name.split(".")[0]
    # tag 去掉 函数 或 相关函数 后缀
    tag = tag.replace("函数", "").replace("相关", "")

    with open(file_path, "r", encoding="utf-8") as f:
        reach_functions = False
        for line in f:
            if not line.strip():
                continue
            if not reach_functions and line.startswith("| ----"):
                reach_functions = True
                continue
            if reach_functions:
                items = line.strip().strip("|").split("|")
                if len(items) == 3:
                    function = Function.from_old_table_row(line)
                    function.tags.append(tag)
                    dest_functions.append(function)
                elif len(items) == 5:
                    function = Function.from_new_table_row(line)
                    dest_functions.append(function)
                else:
                    raise ValueError(f"Invalid row: {line}")


def _write_functions(functions, dest_file_path):
    with open(dest_file_path, "w", encoding="utf-8") as f:
        # 先写表头
        f.write("| 序号 | 地址 | 函数名 | 标签 | 注释  |\n")
        f.write("| ---- | ---- | ------ | ---- | ---- |\n")
        for i, function in enumerate(functions, 1):
            f.write(f"| {i:03} | {function.address:08x} | {function.name} | {','.join(function.tags)} | {function.comment} |\n")


@app.command()
def collect_functions():
    """汇总，每个函数的标签一列添加该函数原所在文件名"""
    functions: list[Function] = []
    for file_name in os.listdir(FUNCTIONS_DIR):
        file_path = os.path.join(FUNCTIONS_DIR, file_name)
        _collect_functions(file_path, functions)

    # 按地址排序
    functions.sort(key=lambda f: f.address)

    _write_functions(functions, DEST_FUNCTIONS_FILE)


if __name__ == "__main__":
    app()
