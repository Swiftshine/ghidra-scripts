# Renames unnamed virtual methods by their offset from the start of the vtable.
# @category Symbol
# @runtime PyGhidra

from ghidra.program.model.symbol import SourceType
from ghidra.util.exception import CancelledException

def create_namespace(namespace_name):
    sym_table           = currentProgram.getSymbolTable()
    parent_namespace    = None

    for part in namespace_name.split("::"):
        cur_ns = sym_table.getNamespace(part, parent_namespace)
        if cur_ns is None:
            cur_ns = sym_table.createNameSpace(parent_namespace, part, SourceType.USER_DEFINED)
        parent_namespace = cur_ns
    
    return parent_namespace

def main():
    try:
        # accessors
        sym_table       = currentProgram.getSymbolTable()
        mem             = currentProgram.getMemory()

        # get info
        vtable_start    = askAddress("Virtual Table Start", "Enter the start address:")
        vtable_end      = askAddress("Virtual Table End", "Enter the end address:")
        namespace_name  = askString("Target Namespace", "Enter the namespace you wish to use:")
        vtable_size     = vtable_end.subtract(vtable_start)
        method_count    = (vtable_size // 4) - 2    # exclude the pointer to rtti and the "this" delta
        methods_start   = vtable_start.add(8)       # same as above ^

        # create namespace
        namespace       = create_namespace(namespace_name)

        for i in range(method_count):
            vtable_entry_addr = methods_start.add(i * 4)
            raw_ptr = mem.getInt(vtable_entry_addr)
            
            if raw_ptr == 0:
                # pure virtual method
                continue

            target_addr = toAddr(raw_ptr)
            symbol = sym_table.getPrimarySymbol(target_addr)

            if symbol is None:
                # no label, create one
                symbol = sym_table.createLabel(target_addr, "temp", namespace, SourceType.USER_DEFINED)
            elif symbol.getSource() != SourceType.DEFAULT:
                # must be unnamed
                continue

            vtable_offset = (i * 4) + 8
            old_name = symbol.getName(True)
            new_name = "vf" + (hex(vtable_offset)[2:]).upper()

            # rename symbol
            symbol.setNameAndNamespace(new_name, namespace, SourceType.USER_DEFINED)
            
            print(f"{old_name} -> {new_name}")

        print("Done!")
    except CancelledException:
        print("Cancelled.")
    except Exception as e:
        print(f"ERROR: {e}")

if __name__ == "__main__":
    main()