# Auto-generated trampoline generator for portal
import sys

COUNT = int(sys.argv[1]) if len(sys.argv) > 1 else 4096

print("// Auto-generated trampoline functions\n")
print("#define PORTAL_TRAMPOLINE_COUNT {0}\n".format(COUNT))
for i in range(COUNT):
    print(f"void portal_tramp_fn_{i:x}(void);")
    print(f"void portal_tramp_fn_{i:x}(void) {{}}")

print("\nvoid (*portal_tramp_table[{0}])(void) = {{".format(COUNT))
for i in range(COUNT):
    print(f"    portal_tramp_fn_{i:x},")
print("};")
