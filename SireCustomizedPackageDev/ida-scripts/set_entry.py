import idaapi


def set_entry_point(entry_address):
    idaapi.add_entry(entry_address, entry_address, "start", 1)


# Example usage:
entry_address = 0x0070A421
set_entry_point(entry_address)
print(f"Entry point set at address: {hex(entry_address)}")
