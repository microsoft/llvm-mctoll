# Handling rodata section data access

It is not always possible to statically (i.e., at static binary translation time) detect accesses into `.rodata`. Consequenytly, abstraction of such accesses as a seperate global variables is not always possible. Contents of `.rodata` themselves can be used either as values or as addresses. It is not always possible to determine statically if a value from `rodata` is used as an address. Following technique, that combines static and runtime function calls, is used to address this situation when statically raising (translating) a binary to LLVM IR by `llvm-mctoll`.

Content of `.rodata` section(s) is abstracted as a global byte array variable. The variable is named `rodata_n`, where `n` is the number of the `.rodata` section. This facilitates handling of binaries with multiple `.rodata` sections.

Any access into `.rodata` section byte is abstracted as `ConstantExpr` that indexes to the offset using `getelementptr`.

Global variable representing `.rodata` content is annotated with metadata of kind `ROData_SecInfo`. The associated `MDNode` contains the start address of the `.rodata` section as found in the source binary being raised.

`Instruction`s that obtain an index (i.e., address) into `.rodata` section are annotated with metadata nodes of kind `ROData_Index`. The associated `MDNode` contains the global byte array value abstracting the `.rodata` content.

`Instruction`s that result in loading from a value with metadata kind `ROData_Index` are annotated with metedata nodes of kind `ROData_Content`. The associated `MDNode` contains the global byte array `Value` that abstracts the `.rodata` content.

Metadata of instructions is copy-propogated (or appropriately modified as needed) during the instruction raising process (which is based on abstract interpretation principles).

In the process of raising the instructions, every time a value representing `.rodata` content (i.e., has the metadata of kind `ROData_Content`) is used as a memory load source (i.e., is used as an address), a call to a function that provides the offset needed to relocate the `.rodata` value is generated. This function is generated at binary translation (raising) time. See `RuntimeFunction::getOrCreateSecOffsetCalcFunction(Module &M)`, for details. The offset value is used to relocate the `.rodata` content used as an address, at runtime. This technique allows for correct handling of content of `.rodata` when used as addresses into `.rodata` section.
