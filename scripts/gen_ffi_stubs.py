#!/usr/bin/env python3
import sys

def generate():
    out = [
        "// GENERATED CODE - DO NOT EDIT",
        "#include <linux/types.h>",
        "",
        "static void dispatch_ffi_call(struct portal_ffi_call *call, uint32_t sig_mask) {",
        "    void *fn = (void *)call->func_ptr;",
        "    switch (sig_mask) {"
    ]
    
    # 0 to 12 arguments = 13 total iterations
    for num_args in range(13):
        for is_ret_64 in (0, 1):
            for arg_bits in range(1 << num_args):
                # Shift bitmask: args (0-11), ret (12), num_args (13+)
                sig_mask = (num_args << 13) | (is_ret_64 << 12) | arg_bits
                
                ret_type = "unsigned long long" if is_ret_64 else "unsigned long"
                arg_types = []
                arg_vars = []
                
                for i in range(num_args):
                    is_64 = (arg_bits & (1 << i)) != 0
                    atype = "unsigned long long" if is_64 else "unsigned long"
                    arg_types.append(atype)
                    arg_vars.append(f"({atype})call->args[{i}]")
                    
                sig = f"{ret_type} (*)({', '.join(arg_types) if num_args > 0 else 'void'})"
                call_expr = f"(({sig})fn)({', '.join(arg_vars)})"
                
                out.append(f"        case {sig_mask}:")
                out.append(f"            call->result = (uint64_t){call_expr};")
                out.append("            break;")
                
    out.extend([
        "        default:",
        "            call->result = (uint64_t)-1; // Invalid signature",
        "            break;",
        "    }",
        "}"
    ])
    
    return "\n".join(out)

if __name__ == "__main__":
    with open(sys.argv[1], "w") as f:
        f.write(generate())