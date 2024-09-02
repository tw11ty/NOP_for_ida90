import ida_bytes
import idautils
import idaapi
import idc

class NopPlugin(idaapi.plugin_t):
    flags = idaapi.PLUGIN_KEEP
    comment = "NOP selected instructions based on architecture"
    help = "This plugin allows you to NOP selected instructions based on the detected architecture"
    wanted_name = "NOPPlugin"
    wanted_hotkey = "Shift+Z"

    def init(self):
        return idaapi.PLUGIN_OK

    def run(self, arg):
        proc_name = idc.get_inf_attr(idc.INF_PROCNAME)
        is_64bit = idc.get_inf_attr(idc.INF_LFLAGS) & idc.LFLG_64BIT
        
        nop_opcode = None

        if proc_name in ['mips', 'mipsb']:
            nop_opcode = b"\x00\x00\x00\x00"  # MIPS NOP
        elif proc_name == 'ARM':
            if is_64bit:
                nop_opcode = b"\xd5\x03\x20\x1f"  # ARM64 NOP (Little Endian)
            else:
                nop_opcode = b"\x00\x00\xa0\xe1"  # ARM32 NOP (MOV R0, R0)
        elif proc_name == 'metapc':
            nop_opcode = b"\x90"  # x86/x86_64 NOP

        if nop_opcode is None:
            print(f"Unsupported architecture: {proc_name}")
            return

        # Check if a range is selected
        selstart, selend = idc.read_selection_start(), idc.read_selection_end()
        if selstart == idc.BADADDR or selend == idc.BADADDR or selstart == selend:
            # No range selected or only one instruction selected
            selstart = selend = idc.here()

        selection = list(idautils.Heads(selstart, selend + 1))  # Include the end address

        if not selection:
            print("No instructions selected.")
            return

        # NOP the selected instructions
        for ea in selection:
            length = ida_bytes.get_item_size(ea)
            patched_nop = nop_opcode * (length // len(nop_opcode))  # Adjust NOP length
            ida_bytes.patch_bytes(ea, patched_nop)

        print(f"NOP applied from {hex(selstart)} to {hex(selend)}.")

    def term(self):
        pass

def PLUGIN_ENTRY():
    return NopPlugin()
