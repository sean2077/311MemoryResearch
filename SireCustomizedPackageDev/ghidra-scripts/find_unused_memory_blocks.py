# TODO write a description for this script
# @author
# @category Python 3
# @keybinding
# @menupath
# @toolbar

from ghidra.program.model.mem import MemoryAccessException


def is_zero_filled(start_addr, end_addr):
    try:
        mem = currentProgram().getMemory()
        current_addr = start_addr
        while current_addr.compareTo(end_addr) <= 0:
            if mem.getByte(current_addr) != 0:
                return False
            current_addr = current_addr.next()
        return True
    except MemoryAccessException as e:
        print(f"Memory access error: {e}")
        return False


def is_not_referenced(start_addr, end_addr):
    refs = currentProgram().getReferenceManager()
    current_addr = start_addr
    while current_addr.compareTo(end_addr) <= 0:
        if refs.hasReferencesTo(current_addr):
            return False
        current_addr = current_addr.next()
    return True


def find_unused_memory_blocks():
    mem = currentProgram().getMemory()
    unused_blocks = []

    for block in mem.getBlocks():
        start_addr = block.getStart()
        end_addr = block.getEnd()
        current_addr = start_addr

        while current_addr.compareTo(end_addr) <= 0:
            next_check_addr = current_addr.add(0x1000)  # 以4KB为单位检查，可以根据需要调整
            if next_check_addr.compareTo(end_addr) > 0:
                next_check_addr = end_addr.add(1)

            if is_zero_filled(current_addr, next_check_addr.subtract(1)) and is_not_referenced(
                current_addr, next_check_addr.subtract(1)
            ):
                unused_blocks.append((current_addr, next_check_addr.subtract(1)))

            current_addr = next_check_addr

    return unused_blocks


def merge_unused_blocks(unused_blocks):
    merged_blocks = []
    unused_blocks.sort(key=lambda x: x[0])
    start_addr, end_addr = unused_blocks[0]
    for i in range(1, len(unused_blocks)):
        if unused_blocks[i][0].compareTo(end_addr.add(1)) == 0:
            end_addr = unused_blocks[i][1]
        else:
            merged_blocks.append((start_addr, end_addr))
            start_addr, end_addr = unused_blocks[i]
    merged_blocks.append((start_addr, end_addr))
    return merged_blocks


def main():
    unused_blocks = find_unused_memory_blocks()
    if unused_blocks:
        merged_blocks = merge_unused_blocks(unused_blocks)
        print("\nMerged unused memory blocks (value=0 and not referenced):")
        for start_addr, end_addr in merged_blocks:
            print(f"Start: {start_addr}, End: {end_addr}")
    else:
        print("No unused memory blocks found.")


# 调用主函数
main()
