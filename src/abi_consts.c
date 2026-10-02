/*
 * Host-ABI enums that no compiled code uses any more, kept in igloo.ko's DWARF.
 *
 * Penguin reads its hypercall constants out of this module's ISF
 * (pyplugins/hyper/consts.py) and asserts that each enum it lists is present.
 * hyperfs_ops and hyperfs_file_ops used to arrive with the hyperfs filesystem,
 * which is gone; this unit carries them so the ISF still satisfies that
 * contract. -fno-eliminate-unused-debug-types (Makefile) makes the compiler
 * emit enums that nothing references.
 */
#include "hyperfs/hyperfs_consts.h"
