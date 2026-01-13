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
        sym_table           = currentProgram.getSymbolTable()
        mem                 = currentProgram.getMemory()
        
        # get base info
        base_vtable_start   = askAddress("Base - Virtual Table Start", "Enter the start address of the base vtable:")
        base_vtable_end     = askAddress("Base - Virtual Table End", "Enter the end address of the base vtable:")
        base_vtable_size    = base_vtable_end.subtract(base_vtable_start)
        base_method_count   = (base_vtable_size // 4) - 2
        base_methods_start  = base_vtable_start.add(8)

        # get derived info
        # we can't always use the start of the vtable due to multiple inheritance, so we use this instead
        derived_methods_start   = askAddress("Derived - Inherited Methods Start", "Enter the address in the vtable where inherited methods begin:")
        derived_namespace_name  = askString("Derived - Namespace", "Enter the full scope-resolved name of derived")

        if len(derived_namespace_name) == 0:
            raise ValueError("Cannot have empty namespace name.")
        
        # create namespace
        namespace = create_namespace(derived_namespace_name)

        # get base functions
        for i in range(base_method_count):
            base_vtable_entry_addr = base_methods_start.add(i * 4)
            base_func_addr = mem.getInt(base_vtable_entry_addr)

            if base_func_addr == 0:
                # pure virtual method
                continue

            base_func = sym_table.getPrimarySymbol(toAddr(base_func_addr))
            
            derived_vtable_entry_addr = derived_methods_start.add(i * 4)
            derived_func_addr = mem.getInt(derived_vtable_entry_addr)

            if derived_func_addr == 0:
                # pure virtual method
                continue
            
            derived_func = sym_table.getPrimarySymbol(toAddr(derived_func_addr))

            if derived_func == base_func:
                # nothing to do
                continue
            
            old_name = derived_func.getName(True)
            new_name = base_func.getName(False)

            if new_name[0] == '~':
                # it's a destructor
                class_name = derived_namespace_name.split("::")[-1]
                new_name = "~" + class_name

            derived_func.setNameAndNamespace(new_name, namespace, SourceType.USER_DEFINED)
            
            print(f"{old_name} -> {derived_namespace_name}::{new_name}")

        print("Done!")        
    except CancelledException:
        print("Cancelled.")
    except Exception as e:
        print(f"ERROR: {e}")

if __name__ == "__main__":
    main()