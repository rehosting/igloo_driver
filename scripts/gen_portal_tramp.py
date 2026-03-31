# Auto-generated trampoline generator for portal
import sys

COUNT = int(sys.argv[1]) if len(sys.argv) > 1 else 4096

print("// Auto-generated trampoline functions\n")
print("#define PORTAL_TRAMPOLINE_COUNT {0}\n".format(COUNT))

# Conditionally apply the NOP padding only for MIPS targets to fix the kprobe branch bug.
# For all other architectures, emit an empty asm block that still embeds the unique ID 
# to universally defeat Identical Code Folding (ICF).
print("#if defined(__mips__)")
print("#define TRAMP_BODY(i) asm volatile(\"nop\\n\\tnop\\n\\tnop\\n\\tnop\" : : \"i\"(i))")
print("#else")
print("#define TRAMP_BODY(i) asm volatile(\"\" : : \"i\"(i))")
print("#endif\n")

for i in range(COUNT):
    print(f"void portal_tramp_fn_{i:x}(void);")
    print(f"void portal_tramp_fn_{i:x}(void) {{ TRAMP_BODY({i}); }}")

print("\nvoid (*portal_tramp_table[{0}])(void) = {{".format(COUNT))
for i in range(COUNT):
    print(f"    portal_tramp_fn_{i:x},")
print("};")
