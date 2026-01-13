# Identify vtable overrides.
# @category Analysis.C++
# @runtime PyGhidra

from ghidra.program.model.symbol import SourceType
from ghidra.util.exception import CancelledException

def create_namespace(namespace_name):
    sym_table   = currentProgram.getSymbolTable()

    parent_namespace = None

    for part in namespace_name.split("::"):
        cur_ns = sym_table.getNamespace(part, parent_namespace)

        if cur_ns is None:
            cur_ns = sym_table.createNameSpace(parent_namespace, part, SourceType.USER_DEFINED)
        
        parent_namespace = cur_ns
    
    return parent_namespace

def main():
    try:
        # accessors
        mem         = currentProgram.getMemory()
        fm          = currentProgram.getFunctionManager()
        
        # get base info
        base_vtable_start       = askAddress("Base - Virtual Table Start", "Enter the start address of the base vtable:")
        base_vtable_end         = askAddress("Base - Virtual Table End", "Enter the end address of the base vtable:")
        base_vtable_size        = base_vtable_end.subtract(base_vtable_start)
        base_method_count       = (base_vtable_size // 4) - 2
        base_methods_start      = base_vtable_start.add(8)

        # get base functions
        base_functions = []
        for i in range(base_method_count):
            vtable_entry_addr = base_methods_start.add(i * 4)
            function_addr = toAddr(mem.getInt(vtable_entry_addr))
            func = fm.getFunctionAt(function_addr)
            base_functions.append(func)

        if all(func is None for func in base_functions):
            # either invalid input or they're all overridden
            raise ValueError("No valid functions were found in the specified address range.")
        
        # get derived info
        # we can't always use the start of the vtable due to multiple inheritance, so we use this instead
        derived_methods_start   = askAddress("Derived - Inherited Methods Start", "Enter the address in the vtable where inherited methods begin:")
        derived_namespace_name  = askString("Derived - Namespace", "Enter the full scope-resolved name of derived")

        # create namespace
        namespace = create_namespace(derived_namespace_name)

        # check for overridden methods
        # if a method is overridden, rename it to [derived]::[base function]
            # if it's a destructor, replace the name
        for i, base_func in enumerate(base_functions):
            if base_func is None:
                # pure virtual method
                continue
            
            vtable_entry_addr = derived_methods_start.add(i * 4)
            derived_function_addr = toAddr(mem.getInt(vtable_entry_addr))
            
            if derived_function_addr == 0:
                # still pure virtual method
                continue

            derived_func = fm.getFunctionAt(derived_function_addr)

            # make it a function if it isn't defined as one
            if derived_func is None:
                derived_func = createFunction(derived_function_addr, None)

            if derived_func == base_func:
                # nothing to do
                continue

            old_name = derived_func.getName(True)
            new_name = base_func.getName(False)

            if new_name[0] == '~':
                # it's a destructor
                class_name = derived_namespace_name.split("::")[-1]
                new_name = "~" + class_name

            derived_symbol = derived_func.getSymbol()
            derived_symbol.setNameAndNamespace(new_name, namespace, SourceType.USER_DEFINED)

            print(f"{old_name} -> {derived_namespace_name}::{new_name}")

        print("Done!")        
    except CancelledException:
        print("Cancelled.")
    except Exception as e:
        print(f"ERROR: {e}")

if __name__ == "__main__":
    main()