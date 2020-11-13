## Raising specific functions in a binary

C functions to include or exclude from being raised may be specified using the `--filter-functions-file` option.

```
llvm-mctoll -d --filter-functions-file=restrict.txt a.out
```

This may be done in a plain text file with `exclude-functions` and `include-functions` sections. Inside each section list the file and function prototype seperated by a colon. Use [LLVM IR function types](https://llvm.org/docs/LangRef.html#function-type) when defining the return and argument types for a function prototype. Here is a simple example.

```
; exclude `int bar(int)` defined in a.out
exclude-functions {
  a.out:i32 bar(i32)   
}

; include `int foo(void)` defined in a.out
include-functions {
  a.out:i32 foo(void)   
}
```

### Specifying prototypes of functions externally referenced in the binary being raised

Binaries (primarily built from C or assembly sources) typically are linked with
shared libraries such as `libc` (on Linux). So, they reference functions whose
protypes are not known from the binary. `llvm-mctoll` can use prototypes while
raising the binary to generate correct calls to such functions in raised LLVM
IR. Standard C header files (such as `/usr/include/stdio.h`) can be specified to
provide prototypes of externally linked functions (such as `printf`) using
command-line options `-I` or `--include-files` For example,

```
llvm-mctoll -d --include-files="/usr/include/stdio.h,/usr/include/stdlib.h,/usr/include/string.h" matmul
````

or
```
llvm-mctoll -d -I /usr/include/stdio.h -I /usr/include/stdlib.h -I /usr/include/string.h matmul
````


It is not necessary to specify an include file from the standard path.  A
user-created file with external function prototypes referenced in the binary
being raised, using standard C syntax, can be used. For example, if the binary
(say, `hello`) uses only the external function `int puts(const char *s);` the
binary (i.e., `hello`) can be raised using the comand

```
llvm-mctoll -d -I  $HOME/myinclude.h hello
```

where `$HOME/myinclude.h` contains

```
int puts(const char *s);
```

## Debugging the raiser

If you build `llvm-mctoll` with assertions enabled you can print the LLVM IR after each pass of the raiser to assist with debugging.
```
llvm-mctoll -d -debug a.out
```

