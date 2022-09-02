include "llvm/Option/OptParser.td"

def help : Flag<["--"], "help">,
  HelpText<"Display available options (--help-hidden for more)">;
def h : Flag<["-"], "h">, Alias<help>;

def help_hidden : Flag<["--"], "help-hidden">,
  Flags<[HelpHidden]>,
  HelpText<"Display all available options">;

def version : Flag<["--"], "version">,
              HelpText<"Display the version of this program">;

def debug : Flag<["-"], "debug">, Flags<[HelpHidden]>;

def raise : Flag<["--"], "raise">,
  HelpText<"Raise machine instruction">;
def : Flag<["-"], "d">, Alias<raise>, HelpText<"Alias for --raise">;

def include_file_EQ : Joined<["--"], "include-file=">,
  HelpText<"Header file with function prototypes using standard C syntax.">;
def : Separate<["--"], "include-file">, Alias<include_file_EQ>;
def : Separate<["-"], "I">, Alias<include_file_EQ>,
  HelpText<"Alias for --include-file">;

def include_files_EQ : Joined<["--"], "include-files=">,
  HelpText<"List of comma-seperated header files with function prototypes using standard C syntax.">;

def filter_functions_file_EQ : Joined<["--"], "filter-functions-file=">,
  HelpText<"Specify which functions to raise via a configuration file.">;
def : Separate<["--"], "filter-functions-file">, Alias<filter_functions_file_EQ>;
def : Separate<["-"], "f">, Alias<filter_functions_file_EQ>,
  HelpText<"Alias for --filter-functions-file">;

def mcpu_EQ : Joined<["--"], "mcpu=">,
  MetaVarName<"cpu-name">,
  HelpText<"Target a specific cpu type (--mcpu=help for details)">,
  Flags<[HelpHidden]>;

def mattr_EQ : Joined<["--"], "mattr=">,
  MetaVarName<"a1,+a2,-a3,...">,
  HelpText<"Target specific attributes (--mattr=help for details)">,
  Flags<[HelpHidden]>;

def outfile_EQ : Joined<["--"], "outfile=">,
  HelpText<"Output filename">;
def : Separate<["--"], "outfile">, Alias<outfile_EQ>;
def : Separate<["-"], "o">, Alias<outfile_EQ>,
  HelpText<"Alias for --outfile">;

class OutputFormatOpts<string base>
  : KeyPathAndMacro<"OutputFormatOpts->", base, "OUTPUT_FORMAT_"> {}

def output_format_EQ : Joined<["--"], "output-format=">,
  HelpText<"Output format: "
    "'ll' (emit llvm text bitcode ('.ll') file) | "
    "'bc' (emit llvm binary bitcode ('.bc') file) | "
    "'null' (emit nothing, for performance testing). "
    "Default is 'll'."
  >,
  Values<"ll,bc,null">,
  NormalizedValuesScope<"OutputFormatTy">,
  NormalizedValues<["LL", "BC", "Null"]>,
  MarshallingInfoEnum<OutputFormatOpts<"OutputFormatTy">, "LL">,
  Flags<[HelpHidden]>;

def run_pass_EQ : Joined<["--"], "run-pass=">,
  MetaVarName<"pass-name">,
  HelpText<"Run compiler only for specified passes (comma separated list)">,
  Flags<[HelpHidden]>;
def : Separate<["--"], "run-pass">, Alias<run_pass_EQ>;

def start_address_EQ : Joined<["--"], "start-address=">,
  MetaVarName<"address">,
  HelpText<"Disassemble beginning at address">,
  Flags<[HelpHidden]>;
def : Separate<["--"], "start-address">, Alias<start_address_EQ>;
def stop_address_EQ : Joined<["--"], "stop-address=">,
  MetaVarName<"address">,
  HelpText<"Stop disassembly at address">,
  Flags<[HelpHidden]>;
def : Separate<["--"], "stop-address">, Alias<stop_address_EQ>;

def section_EQ : Joined<["--"], "section=">,
  HelpText<"Operate on the specified sections only. "
           "With --macho dump segment,section">,
  Flags<[HelpHidden]>;
def : Separate<["--"], "section">, Alias<section_EQ>;
def : Separate<["-"], "j">, Alias<section_EQ>,
  HelpText<"Alias for --section">,
  Flags<[HelpHidden]>;

def sysyroot_EQ : Joined<["--"], "sysroot=">,
  HelpText<"Toolchain sysroot">;
def : Separate<["--"], "sysroot">, Alias<sysyroot_EQ>;

def target_EQ : Separate<["-"], "target">,
  HelpText<"Target triple to disassemble for, "
            "see --version for available targets">,
  Flags<[HelpHidden]>;
