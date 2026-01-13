# vtable scripts

### name_virtual_methods_by_offset
If there isn't an existing user-defined name for a function, it will be named by its offset relative to the beginning of the vtable, i.e. `vf8`, `vfC`, `vf10`, and so on.


### rename_overrides
Given the base vtable address range and the address of the start of the inherited methods within the derived vtable, overridden methods will be automatically renamed.