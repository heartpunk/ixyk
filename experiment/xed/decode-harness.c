#include <xed/xed-interface.h>

/* Decoder scope: initialized XED tables, caller-provided input and output,
 * fixed x86-64 machine mode. No formatting or encoder machinery. */
__attribute__((noinline))
xed_error_enum_t ixyk_decode_bytes(const xed_uint8_t *bytes, unsigned length,
                                  xed_decoded_inst_t *out) {
    xed_decoded_inst_zero(out);
    xed_decoded_inst_set_mode(out, XED_MACHINE_MODE_LONG_64,
                             XED_ADDRESS_WIDTH_64b);
    return xed_decode(out, bytes, length);
}

int main(void) {
    xed_decoded_inst_t decoded;
    const xed_uint8_t nop[] = {0x90};
    xed_tables_init();
    return ixyk_decode_bytes(nop, sizeof nop, &decoded) != XED_ERROR_NONE;
}
