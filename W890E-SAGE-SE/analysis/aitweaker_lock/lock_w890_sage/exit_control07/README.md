# Original exit control flow: W890E-SAGE SE 0603

Ten local cases execute the unchanged original AMITSE BrowserLoop tail, beginning at RVA 1995F. Existing genuine REA output at `navigation/rea_text/W890-seeded-loop190f4.c` supplies the surrounding function context; the exact original bytes are independently decoded and executed here.

Returning an error from cleanup 748C does not stop the reset branch. The next instructions ignore that result, invoke another OEM callback and proceed to cold or warm ResetSystem. Both reset and ordinary exit paths also perform earlier work before reaching 748C: render cleanup, optional buffer release, an OEM callback, protocol removal and clearing BAAB8. Ordinary exit additionally frees history and clears its counters before its cleanup call. A late refusal therefore cannot be described as cancellation back to an intact BIOS interface.

At the 1995F flag check, an exit flag of zero still branches to the existing input loop at 196FF with none of those tail effects. This identifies an earlier candidate boundary, not a finished guard. A production change still needs private runtime ownership, complete preflight before effects, preservation of the active page and pending save/reset state, and tests through the real input loop and teardown. Earlier writes cannot be undone by cancelling this tail.

The tests explicitly model firmware services, render/OEM callee bodies and the cleanup callee's return value. They stop at ResetSystem, the normal epilogue, or the input-loop continuation. They do not execute an actual reset, full GUI, destructor or password operation. No original binary, frozen component, aggregate or firmware image is modified.
