# W890E-SAGE SE 0603: fixed source-page-table observations

This component provides read-only diagnostic observations, not password enforcement or a flashable image. It is intended for the separately reviewed Delta07 carrier.

`s7_capture_pair` receives the existing HII06 bounded-copy/allocation adapter and an enumerated AMITSE image span. Each of its two observations independently measures the original AMITSE code with the frozen HII06 profile. A caller-supplied match boolean is never accepted.

After that measurement it reads five fixed image globals and fourteen fixed source-SPF field extents. Source tables and current/reallocated tables remain distinct. The source layout must match the original constants before deeper fixed fields are read. The possible one-past offset overlaps the first page's HII field; that field is sampled but never followed. No computed GUID target or adjacent allocation is read.

The packed wire format is two 70-byte snapshots (140 bytes total). Each field has an independent validity bit. Failed reads leave the field unavailable, including adapters that partially modify their output before reporting failure. Changes in fields or availability/status mark both observations unstable. A zero candidate refers to the low 32 bits, matching the original offset load. Complete/stable observations confer no authorization.

Validation: 35 cases execute the compiled C implementation, SHA implementation and original PE/SPF bytes against an explicit memory-read model. These include bad profiles, null/overflow pointers, read failures, partial failed copies, changed code/data/availability between observations and nonzero candidates. Read ranges and allocation guards are checked. An independent review replayed all 35 cases and exercised 14 malformed decoder inputs. See the bound reports in the component manifest.

Limits: post-Setup observations do not establish the values during initial parsing; a self-declared or mapped span does not establish allocation ownership; these local tests do not qualify the final UEFI adapter, carrier, firmware startup, password lock or flashing path. The component does not invoke firmware business callbacks or write settings, passwords, files or firmware. Its DLL is a local test artifact only.
