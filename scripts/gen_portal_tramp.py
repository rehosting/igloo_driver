# Auto-generated trampoline generator for portal
import sys

COUNT = int(sys.argv[1]) if len(sys.argv) > 1 else 8192

print("// Auto-generated trampoline functions\n")
print("#define PORTAL_TRAMPOLINE_COUNT {0}\n".format(COUNT))

for i in range(COUNT):
    print(f"void portal_tramp_fn_{i:x}(void);")
    # Unconditionally pad with NOPs for all architectures to prevent 
    # kprobes from attaching to naked return/branch instructions.
    print(f"void portal_tramp_fn_{i:x}(void) {{ asm volatile(\"nop\\n\\tnop\\n\\tnop\\n\\tnop\" : : \"i\"({i})); }}")

print("\nvoid (*portal_tramp_table[{0}])(void) = {{".format(COUNT))
for i in range(COUNT):
    print(f"    portal_tramp_fn_{i:x},")
print("};")
