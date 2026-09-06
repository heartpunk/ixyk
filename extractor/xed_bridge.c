// SPDX-FileCopyrightText: 2026 Sophie Smithburg
// SPDX-License-Identifier: GPL-3.0-or-later

// A process boundary around XED's public API, not instruction semantics.
#include <xed/xed-interface.h>
#include <errno.h>
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <xed/ixyk-enc2-dispatch.h>
#include <xed/ixyk-enc2-fuzz.h>

static void fail(const char *message) {
    fprintf(stderr, "%s\n", message);
    exit(1);
}

static int64_t integer(const char *text) {
    char *end;
    errno = 0;
    int64_t value = strtoll(text, &end, 0);
    if (errno || end == text || *end) fail("invalid integer");
    return value;
}

static void register_json(xed_reg_enum_t reg) {
    printf("{\"value\":%u,\"name\":\"%s\",\"class\":\"%s\",\"width\":%u,"
           "\"parent\":\"%s\"}",
           (unsigned)reg, xed_reg_enum_t2str(reg),
           xed_reg_class_enum_t2str(xed_reg_class(reg)),
           xed_get_register_width_bits64(reg),
           xed_reg_enum_t2str(xed_get_largest_enclosing_register(reg)));
}

static void decode(xed_decoded_inst_t *inst, const unsigned char *bytes,
                   unsigned length) {
    xed_decoded_inst_zero(inst);
    xed_decoded_inst_set_mode(inst, XED_MACHINE_MODE_LONG_64,
                             XED_ADDRESS_WIDTH_64b);
    xed_error_enum_t error = xed_decode(inst, bytes, length);
    if (error != XED_ERROR_NONE) fail(xed_error_enum_t2str(error));
    if (xed_decoded_inst_get_length(inst) != length)
        fail("expected exactly one instruction");
}

static int matches(const xed_decoded_inst_t *wanted, const unsigned char *bytes,
                   unsigned length) {
    if (!length || length > XED_MAX_INSTRUCTION_BYTES ||
        length != xed_decoded_inst_get_length(wanted)) return 0;
    xed_decoded_inst_t actual;
    xed_decoded_inst_zero(&actual);
    xed_decoded_inst_set_mode(&actual, XED_MACHINE_MODE_LONG_64, XED_ADDRESS_WIDTH_64b);
    if (xed_decode(&actual, bytes, length) != XED_ERROR_NONE) return 0;
#define SAME(getter) if (getter(wanted) != getter(&actual)) return 0
    SAME(xed_decoded_inst_get_iform_enum);
    SAME(xed_decoded_inst_get_length);
    SAME(xed_decoded_inst_get_operand_width);
    SAME(xed_decoded_inst_get_branch_displacement);
    SAME(xed_decoded_inst_get_branch_displacement_width_bits);
    SAME(xed_decoded_inst_get_unsigned_immediate);
    SAME(xed_decoded_inst_get_second_immediate);
    SAME(xed_decoded_inst_get_immediate_width_bits);
    SAME(xed_decoded_inst_get_immediate_is_signed);
    SAME(xed_operand_values_has_lock_prefix);
    SAME(xed_operand_values_has_rep_prefix);
    SAME(xed_operand_values_has_repne_prefix);
    SAME(xed_operand_values_has_address_size_prefix);
    SAME(xed_operand_values_has_66_prefix);
    SAME(xed_operand_values_has_rexw_prefix);
    SAME(xed_operand_values_segment_prefix);
    SAME(xed_decoded_inst_zeroing);
    SAME(xed_decoded_inst_uses_embedded_broadcast);
    SAME(xed3_operand_get_roundc);
    SAME(xed3_operand_get_sae);
    SAME(xed3_operand_get_nf);
    SAME(xed3_operand_get_nd);
    SAME(xed3_operand_get_dfv);
#undef SAME
    const xed_inst_t *form = xed_decoded_inst_inst(wanted);
    for (unsigned i = 0; i < xed_inst_noperands(form); ++i) {
        xed_operand_enum_t name = xed_operand_name(xed_inst_operand(form, i));
        if (xed_decoded_inst_operand_length_bits(wanted, i) !=
            xed_decoded_inst_operand_length_bits(&actual, i)) return 0;
        if (xed_operand_is_register(name) &&
            xed_decoded_inst_get_reg(wanted, name) !=
            xed_decoded_inst_get_reg(&actual, name)) return 0;
    }
    for (unsigned i = 0; i < 2; ++i) {
        if (xed_decoded_inst_get_base_reg(wanted, i) != xed_decoded_inst_get_base_reg(&actual, i) ||
            xed_decoded_inst_get_seg_reg(wanted, i) != xed_decoded_inst_get_seg_reg(&actual, i)) return 0;
    }
    return xed_decoded_inst_get_index_reg(wanted, 0) == xed_decoded_inst_get_index_reg(&actual, 0) &&
        xed_decoded_inst_get_scale(wanted, 0) == xed_decoded_inst_get_scale(&actual, 0) &&
        xed_decoded_inst_get_memory_displacement(wanted, 0) == xed_decoded_inst_get_memory_displacement(&actual, 0) &&
        xed_decoded_inst_get_memory_displacement_width_bits(wanted, 0) == xed_decoded_inst_get_memory_displacement_width_bits(&actual, 0);
}

static void describe(xed_decoded_inst_t *inst, const unsigned char *bytes,
                     unsigned length) {
    const xed_inst_t *form = xed_decoded_inst_inst(inst);
    printf("{\"hex\":\"");
    for (unsigned i = 0; i < length; ++i) printf("%02x", bytes[i]);
    printf("\",\"length\":%u,\"form\":\"%s\",\"iclass\":\"%s\","
           "\"operands\":[", length,
           xed_iform_enum_t2str(xed_decoded_inst_get_iform_enum(inst)),
           xed_iclass_enum_t2str(xed_decoded_inst_get_iclass(inst)));
    for (unsigned i = 0; i < xed_inst_noperands(form); ++i) {
        const xed_operand_t *op = xed_inst_operand(form, i);
        xed_operand_enum_t name = xed_operand_name(op);
        if (i) printf(",");
        printf("{\"name\":\"%s\",\"visibility\":\"%s\","
               "\"width\":%u,\"action\":\"%s\",\"register\":",
               xed_operand_enum_t2str(name),
               xed_operand_visibility_enum_t2str(xed_operand_operand_visibility(op)),
               xed_decoded_inst_operand_length_bits(inst, i),
               xed_operand_action_enum_t2str(xed_operand_rw(op)));
        register_json(xed_operand_is_register(name)
                      ? xed_decoded_inst_get_reg(inst, name) : XED_REG_INVALID);
        printf("}");
    }
    printf("],\"base\":");
    register_json(xed_decoded_inst_get_base_reg(inst, 0));
    printf(",\"index\":");
    register_json(xed_decoded_inst_get_index_reg(inst, 0));
    printf(",\"scale\":%u,\"displacement\":%" PRId64
           ",\"displacement_width\":%u,\"branch\":%" PRId64
           ",\"branch_width\":%u,\"immediate\":%" PRIu64
           ",\"immediate_signed\":%s,\"immediate_width\":%u}\n",
           xed_decoded_inst_get_scale(inst, 0),
           xed_decoded_inst_get_memory_displacement(inst, 0),
           xed_decoded_inst_get_memory_displacement_width_bits(inst, 0),
           xed_decoded_inst_get_branch_displacement(inst),
           xed_decoded_inst_get_branch_displacement_width_bits(inst),
           xed_decoded_inst_get_unsigned_immediate(inst),
           xed_decoded_inst_get_immediate_is_signed(inst) ? "true" : "false",
           xed_decoded_inst_get_immediate_width_bits(inst));
}

int main(int argc, char **argv) {
    xed_tables_init();
    const unsigned count = sizeof(ixyk_fuzz_argc) / sizeof(ixyk_fuzz_argc[0]);
    if (argc == 3 && strcmp(argv[1], "forms") == 0) {
        unsigned found = 0;
        printf("[");
        for (unsigned i = 0; i < count; ++i) {
            if (strcmp(argv[2], ixyk_fuzz_classes[i])) continue;
            printf("%s%s", found++ ? "," : "", ixyk_fuzz_metadata[i]);
        }
        printf("]\n");
        return 0;
    }
    if (argc >= 3 && strcmp(argv[1], "fuzz") == 0) {
        int64_t index = integer(argv[2]);
        if (index < 0 || index >= count || argc - 3 != ixyk_fuzz_argc[index])
            fail("invalid encoder argument count");
        uint64_t values[32];
        if (argc - 3 > 32) fail("too many encoder arguments");
        for (int i = 3; i < argc; ++i) {
            char *end; errno = 0;
            values[i-3] = strtoull(argv[i], &end, 0);
            if (errno || end == argv[i] || *end) fail("invalid encoder argument");
        }
        unsigned char bytes[64];
        unsigned length = ixyk_fuzz_encoders[index](values, bytes);
        if (!length || length > XED_MAX_INSTRUCTION_BYTES) fail("invalid encoding length");
        xed_decoded_inst_t inst;
        decode(&inst, bytes, length);
        if (strcmp(xed_iclass_enum_t2str(xed_decoded_inst_get_iclass(&inst)),
                   ixyk_fuzz_classes[index])) fail("encoding changed instruction class");
        describe(&inst, bytes, length);
        return 0;
    }

    if (argc == 2 && !strcmp(argv[1], "registers")) {
        printf("[");
        for (int r = XED_REG_INVALID + 1; r < XED_REG_LAST; ++r) {
            if (r != XED_REG_INVALID + 1) printf(",");
            register_json((xed_reg_enum_t)r);
        }
        printf("]\n");
        return 0;
    }
    if (argc < 2) fail("expected instruction hex and optional FIELD VALUE pairs");
    /* ENC2 writes into caller storage; validate its result before accepting it. */
    unsigned char bytes[64];
    size_t chars = strlen(argv[1]);
    if (!chars || chars % 2 || chars > XED_MAX_INSTRUCTION_BYTES * 2) fail("invalid hex length");
    unsigned length = chars / 2;
    for (unsigned i = 0; i < length; ++i) {
        char pair[3] = {argv[1][i * 2], argv[1][i * 2 + 1], 0};
        char *end;
        unsigned long value = strtoul(pair, &end, 16);
        if (*end || end != pair + 2) fail("invalid instruction hex");
        bytes[i] = value;
    }
    xed_decoded_inst_t inst;
    decode(&inst, bytes, length);
    if (argc > 2) {
        if ((argc - 2) % 2) fail("expected FIELD VALUE pairs");
        unsigned branch_width = xed_decoded_inst_get_branch_displacement_width(&inst);
        unsigned disp_width = xed_decoded_inst_get_memory_displacement_width(&inst, 0);
        unsigned imm_width = xed_decoded_inst_get_immediate_width(&inst);
        for (int i = 2; i < argc; i += 2) {
            xed_operand_enum_t field = str2xed_operand_enum_t(argv[i]);
            const char *value = argv[i + 1];
            if (xed_operand_is_register(field) || field == XED_OPERAND_BASE0 ||
                field == XED_OPERAND_INDEX) {
                xed_reg_enum_t reg = str2xed_reg_enum_t(value);
                if (reg == XED_REG_INVALID) fail("invalid register");
                if (field == XED_OPERAND_BASE0) xed_encoder_request_set_base0(&inst, reg);
                else if (field == XED_OPERAND_INDEX) xed_encoder_request_set_index(&inst, reg);
                else xed_encoder_request_set_reg(&inst, field, reg);
            } else if (field == XED_OPERAND_RELBR) {
                if (!branch_width) fail("no encoded relative branch operand");
                xed_encoder_request_set_branch_displacement(&inst, integer(value), branch_width);
            } else if (field == XED_OPERAND_DISP) {
                if (!disp_width) fail("no encoded memory displacement");
                xed_encoder_request_set_memory_displacement(&inst, integer(value), disp_width);
            } else if (field == XED_OPERAND_SCALE) {
                int64_t scale = integer(value);
                if (scale != 1 && scale != 2 && scale != 4 && scale != 8)
                    fail("invalid address scale");
                xed_encoder_request_set_scale(&inst, scale);
            } else if (field == XED_OPERAND_IMM0) {
                if (!imm_width) fail("no encoded immediate operand");
                char *end;
                errno = 0;
                uint64_t immediate = strtoull(value, &end, 0);
                if (errno || end == value || *end) fail("invalid immediate");
                /* Preserve the decoded immediate width and signedness. */
                xed3_operand_set_uimm0(&inst, immediate);
            } else fail("unsupported encoding field");
        }
        if (!ixyk_enc2_encode(&inst, bytes, &length, matches))
            fail("no ENC2 candidate preserves the instruction form and requested operands");
        decode(&inst, bytes, length);
    }
    describe(&inst, bytes, length);
    return 0;
}
