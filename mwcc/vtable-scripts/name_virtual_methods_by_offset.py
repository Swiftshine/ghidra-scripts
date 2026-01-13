# Renames unnamed virtual methods by their offset from the start of the vtable.
# @category Symbol
# @runtime PyGhidra

from ghidra.program.model.symbol import SourceType
from ghidra.util.exception import CancelledException

def main():
    try:
        # accessors
        mem         = currentProgram.getMemory()
        fm          = currentProgram.getFunctionManager()
        sym_table   = currentProgram.getSymbolTable()

        # get info
        base_start      = askAddress("Base Virtual Table Start", "Enter the start address:")
        base_end        = askAddress("Base Virtual Table End", "Enter the end address:")
        namespace_name  = askString("Target Namespace", "Enter the namespace you wish to use:")
        vtable_size     = base_end.subtract(base_start)
        method_count    = (vtable_size // 4) - 2    # exclude the pointer to rtti and the "this" delta
        methods_start   = base_start.add(8)         # same as above ^

        # get functions
        funcs = []
        for i in range(method_count):
            vtable_entry_addr = methods_start.add(i * 4)
            function_addr = toAddr(mem.getInt(vtable_entry_addr))
            target = fm.getFunctionAt(function_addr)

            # make it a function if it isn't defined as one
            if target is None:
                target = createFunction(function_addr, None)
            
            funcs.append(target)
        
        if all(func is None for func in funcs):
            raise ValueError("No valid functions were found in the specified address range.")

        # create namespace
        parent_namespace = None

        for part in namespace_name.split("::"):
            cur_ns = sym_table.getNamespace(part, parent_namespace)

            if cur_ns is None:
                cur_ns = sym_table.createNameSpace(parent_namespace, part, SourceType.USER_DEFINED)
            
            parent_namespace = cur_ns

        namespace = parent_namespace

        # rename functions
        for i, func in enumerate(funcs):
            # ignore if no function or if function is named
            if func is None:
                continue
            
            if func.getSymbol().getSource() != SourceType.DEFAULT:
                continue
            
            vtable_offset = (i * 4) + 8
            old_name = func.getName(True)
            new_name = "vf" + (hex(vtable_offset)[2:]).upper()

            symbol = func.getSymbol()
            symbol.setNameAndNamespace(new_name, namespace, SourceType.USER_DEFINED)

            print(f"{old_name} -> {new_name}")

        print("Done!")
    except CancelledException:
        print("Cancelled.")
    except Exception as e:
        print(f"ERROR: {e}")

if __name__ == "__main__":
    main()