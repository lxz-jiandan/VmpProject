#ifndef VMPROTECT_PATCHBAY_ENTRY_H
#define VMPROTECT_PATCHBAY_ENTRY_H

// Returns true when cmd should be handled by the embedded patchbay CLI.
bool vmprotect_is_patchbay_command(const char* cmd);

// Embedded patchbay CLI entry.
int vmprotect_patchbay_entry(int argc, char* argv[]);

#endif // VMPROTECT_PATCHBAY_ENTRY_H
