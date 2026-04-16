#!/usr/bin/env python3
import sys

def generate():
    out = [
        "// GENERATED CODE - DO NOT EDIT",
        "#include <linux/types.h>",
        "#include <asm/bitsperlong.h>",
        "",
        "/* ========================================================================= */",
        "/* 64-BIT FAST PATH                                                          */",
        "/* ========================================================================= */",
        "#if BITS_PER_LONG == 64",
        "",
        "typedef uint64_t (*generic_ffi_t)(uint64_t, uint64_t, uint64_t, uint64_t,",
        "                                  uint64_t, uint64_t, uint64_t, uint64_t);",
        "",
        "static void dispatch_ffi_call(struct portal_ffi_call *call, uint32_t sig_mask) {",
        "    generic_ffi_t fn = (generic_ffi_t)(unsigned long)call->func_ptr;",
        "    call->result = fn(call->args[0], call->args[1], call->args[2], call->args[3],",
        "                      call->args[4], call->args[5], call->args[6], call->args[7]);",
        "}",
        "",
        "/* ========================================================================= */",
        "/* 32-BIT COMPATIBILITY PATH                                                 */",
        "/* ========================================================================= */",
        "#else",
        ""
    ]
    
    # Generate individual functions for each arg count (0 to 8)
    for num_args in range(9):
        func_name = f"dispatch_ffi_{num_args}"
        out.append(f"static void {func_name}(struct portal_ffi_call *call, uint32_t arg_bits) {{")
        out.append(f"    void *fn = (void *)(unsigned long)call->func_ptr;")
        out.append(f"    switch (arg_bits) {{")
        
        # Only iterate the bits valid for this specific num_args
        for arg_bits in range(1 << num_args):
            arg_types = []
            arg_vars = []
            
            for i in range(num_args):
                # Dynamically set EACH argument as 32-bit or 64-bit based on the bitmask
                is_64 = (arg_bits & (1 << i)) != 0
                atype = "unsigned long long" if is_64 else "unsigned long"
                arg_types.append(atype)
                arg_vars.append(f"({atype})call->args[{i}]")
                
            # ALWAYS assume unsigned long long return to halve the branch combinations
            sig = f"unsigned long long (*)({', '.join(arg_types) if num_args > 0 else 'void'})"
            call_expr = f"(({sig})fn)({', '.join(arg_vars)})"
            
            out.append(f"        case {arg_bits}:")
            out.append(f"            call->result = (uint64_t){call_expr};")
            out.append("            break;")
            
        out.extend([
            "        default:",
            "            call->result = (uint64_t)-1;",
            "            break;",
            "    }",
            "}",
            ""
        ])
            
    # Generate the main dispatch function
    out.extend([
        "static void dispatch_ffi_call(struct portal_ffi_call *call, uint32_t sig_mask) {",
        "    uint32_t num_args = sig_mask >> 8;",
        "    uint32_t arg_bits = sig_mask & 0xFF;",
        "    switch (num_args) {"
    ])
    
    for num_args in range(9):
        out.append(f"        case {num_args}:")
        out.append(f"            dispatch_ffi_{num_args}(call, arg_bits);")
        out.append(f"            break;")
        
    out.extend([
        "        default:",
        "            call->result = (uint64_t)-1;",
        "            break;",
        "    }",
        "}",
        "",
        "#endif // BITS_PER_LONG == 64"
    ])
    
    return "\n".join(out)

if __name__ == "__main__":
    with open(sys.argv[1], "w") as f:
        f.write(generate())