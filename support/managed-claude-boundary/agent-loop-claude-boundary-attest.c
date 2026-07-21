/*
 * Reviewed managed-Claude SessionStart boundary attestation helper.
 *
 * This source has no library dependencies beyond libc and is suitable for a
 * static build.  A provisioner should compile it with a reviewed C compiler,
 * install the resulting binary root:root mode 0555 at
 * /usr/local/libexec/agent-loop-claude-boundary-attest, and separately install
 * managed-settings.json root:root mode 0444 or 0644 beneath /etc/claude-code.
 *
 * Failure is intentionally silent.  Success writes exactly one fixed marker
 * to stderr and exits 2: Claude documents exit 2 as user-visible hook stderr
 * that is not added to the model context for SessionStart hooks.
 */

#define _POSIX_C_SOURCE 200809L

#include <errno.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define MAX_INPUT_BYTES ((size_t)65536)
#define MAX_JSON_DEPTH 32U
#define MAX_COLLECTION_ITEMS ((size_t)1024)
#define MAX_TOP_LEVEL_KEYS ((size_t)64)
#define MAX_KEY_BYTES ((size_t)128)
#define MAX_VALUE_BYTES ((size_t)256)

#define FAILURE_EXIT 3
#define SUCCESS_EXIT 2

static const char success_marker[] =
    "AGENT_LOOP_MANAGED_CLAUDE_BOUNDARY_OK:reviewed-managed-boundary-v1:"
    "credential_absent:scrub=1";

typedef struct {
    const unsigned char *data;
    size_t length;
    size_t cursor;
} JsonParser;

typedef struct {
    unsigned char data[MAX_KEY_BYTES];
    size_t length;
} SeenKey;

static void skip_whitespace(JsonParser *parser)
{
    while (parser->cursor < parser->length) {
        unsigned char value = parser->data[parser->cursor];
        if (value != (unsigned char)' ' && value != (unsigned char)'\t' &&
            value != (unsigned char)'\n' && value != (unsigned char)'\r') {
            break;
        }
        parser->cursor++;
    }
}

static bool consume(JsonParser *parser, unsigned char expected)
{
    if (parser->cursor >= parser->length || parser->data[parser->cursor] != expected) {
        return false;
    }
    parser->cursor++;
    return true;
}

static bool append_byte(
    unsigned char *output,
    size_t capacity,
    size_t *length,
    unsigned char value)
{
    if (output != NULL) {
        if (*length >= capacity) {
            return false;
        }
        output[*length] = value;
    }
    (*length)++;
    return true;
}

static bool append_codepoint(
    unsigned char *output,
    size_t capacity,
    size_t *length,
    uint32_t codepoint)
{
    if (codepoint <= UINT32_C(0x7f)) {
        return append_byte(output, capacity, length, (unsigned char)codepoint);
    }
    if (codepoint <= UINT32_C(0x7ff)) {
        return append_byte(
                   output,
                   capacity,
                   length,
                   (unsigned char)(UINT32_C(0xc0) | (codepoint >> 6))) &&
            append_byte(
                   output,
                   capacity,
                   length,
                   (unsigned char)(UINT32_C(0x80) | (codepoint & UINT32_C(0x3f))));
    }
    if (codepoint <= UINT32_C(0xffff)) {
        if (codepoint >= UINT32_C(0xd800) && codepoint <= UINT32_C(0xdfff)) {
            return false;
        }
        return append_byte(
                   output,
                   capacity,
                   length,
                   (unsigned char)(UINT32_C(0xe0) | (codepoint >> 12))) &&
            append_byte(
                   output,
                   capacity,
                   length,
                   (unsigned char)(
                       UINT32_C(0x80) | ((codepoint >> 6) & UINT32_C(0x3f)))) &&
            append_byte(
                   output,
                   capacity,
                   length,
                   (unsigned char)(UINT32_C(0x80) | (codepoint & UINT32_C(0x3f))));
    }
    if (codepoint <= UINT32_C(0x10ffff)) {
        return append_byte(
                   output,
                   capacity,
                   length,
                   (unsigned char)(UINT32_C(0xf0) | (codepoint >> 18))) &&
            append_byte(
                   output,
                   capacity,
                   length,
                   (unsigned char)(
                       UINT32_C(0x80) | ((codepoint >> 12) & UINT32_C(0x3f)))) &&
            append_byte(
                   output,
                   capacity,
                   length,
                   (unsigned char)(
                       UINT32_C(0x80) | ((codepoint >> 6) & UINT32_C(0x3f)))) &&
            append_byte(
                   output,
                   capacity,
                   length,
                   (unsigned char)(UINT32_C(0x80) | (codepoint & UINT32_C(0x3f))));
    }
    return false;
}

static int hex_value(unsigned char value)
{
    if (value >= (unsigned char)'0' && value <= (unsigned char)'9') {
        return (int)(value - (unsigned char)'0');
    }
    if (value >= (unsigned char)'a' && value <= (unsigned char)'f') {
        return 10 + (int)(value - (unsigned char)'a');
    }
    if (value >= (unsigned char)'A' && value <= (unsigned char)'F') {
        return 10 + (int)(value - (unsigned char)'A');
    }
    return -1;
}

static bool parse_hex_quad(JsonParser *parser, uint32_t *result)
{
    uint32_t value = 0;
    size_t index;

    if (parser->length - parser->cursor < 4U) {
        return false;
    }
    for (index = 0; index < 4U; index++) {
        int digit = hex_value(parser->data[parser->cursor + index]);
        if (digit < 0) {
            return false;
        }
        value = (value << 4) | (uint32_t)digit;
    }
    parser->cursor += 4U;
    *result = value;
    return true;
}

static bool parse_raw_codepoint(JsonParser *parser, uint32_t *result)
{
    unsigned char first;
    uint32_t value;
    size_t continuation_count;
    size_t index;

    if (parser->cursor >= parser->length) {
        return false;
    }
    first = parser->data[parser->cursor++];
    if (first < UINT8_C(0x80)) {
        if (first < UINT8_C(0x20)) {
            return false;
        }
        *result = first;
        return true;
    }
    if (first >= UINT8_C(0xc2) && first <= UINT8_C(0xdf)) {
        value = (uint32_t)(first & UINT8_C(0x1f));
        continuation_count = 1U;
    } else if (first >= UINT8_C(0xe0) && first <= UINT8_C(0xef)) {
        value = (uint32_t)(first & UINT8_C(0x0f));
        continuation_count = 2U;
    } else if (first >= UINT8_C(0xf0) && first <= UINT8_C(0xf4)) {
        value = (uint32_t)(first & UINT8_C(0x07));
        continuation_count = 3U;
    } else {
        return false;
    }
    if (parser->length - parser->cursor < continuation_count) {
        return false;
    }
    for (index = 0; index < continuation_count; index++) {
        unsigned char next = parser->data[parser->cursor++];
        if ((next & UINT8_C(0xc0)) != UINT8_C(0x80)) {
            return false;
        }
        value = (value << 6) | (uint32_t)(next & UINT8_C(0x3f));
    }
    if ((continuation_count == 2U && value < UINT32_C(0x800)) ||
        (continuation_count == 3U && value < UINT32_C(0x10000)) ||
        value > UINT32_C(0x10ffff) ||
        (value >= UINT32_C(0xd800) && value <= UINT32_C(0xdfff))) {
        return false;
    }
    *result = value;
    return true;
}

static bool parse_string(
    JsonParser *parser,
    unsigned char *output,
    size_t capacity,
    size_t *output_length)
{
    size_t decoded_length = 0;

    if (!consume(parser, (unsigned char)'"')) {
        return false;
    }
    while (parser->cursor < parser->length) {
        uint32_t codepoint;
        unsigned char value = parser->data[parser->cursor];

        if (value == (unsigned char)'"') {
            parser->cursor++;
            *output_length = decoded_length;
            return true;
        }
        if (value != (unsigned char)'\\') {
            if (!parse_raw_codepoint(parser, &codepoint) ||
                !append_codepoint(output, capacity, &decoded_length, codepoint)) {
                return false;
            }
            continue;
        }
        parser->cursor++;
        if (parser->cursor >= parser->length) {
            return false;
        }
        value = parser->data[parser->cursor++];
        switch (value) {
        case (unsigned char)'"':
        case (unsigned char)'\\':
        case (unsigned char)'/':
            codepoint = value;
            break;
        case (unsigned char)'b':
            codepoint = UINT32_C(0x08);
            break;
        case (unsigned char)'f':
            codepoint = UINT32_C(0x0c);
            break;
        case (unsigned char)'n':
            codepoint = UINT32_C(0x0a);
            break;
        case (unsigned char)'r':
            codepoint = UINT32_C(0x0d);
            break;
        case (unsigned char)'t':
            codepoint = UINT32_C(0x09);
            break;
        case (unsigned char)'u': {
            uint32_t second;
            if (!parse_hex_quad(parser, &codepoint)) {
                return false;
            }
            if (codepoint >= UINT32_C(0xd800) && codepoint <= UINT32_C(0xdbff)) {
                if (parser->length - parser->cursor < 6U ||
                    parser->data[parser->cursor] != (unsigned char)'\\' ||
                    parser->data[parser->cursor + 1U] != (unsigned char)'u') {
                    return false;
                }
                parser->cursor += 2U;
                if (!parse_hex_quad(parser, &second) || second < UINT32_C(0xdc00) ||
                    second > UINT32_C(0xdfff)) {
                    return false;
                }
                codepoint = UINT32_C(0x10000) +
                    ((codepoint - UINT32_C(0xd800)) << 10) +
                    (second - UINT32_C(0xdc00));
            } else if (codepoint >= UINT32_C(0xdc00) &&
                       codepoint <= UINT32_C(0xdfff)) {
                return false;
            }
            break;
        }
        default:
            return false;
        }
        if (!append_codepoint(output, capacity, &decoded_length, codepoint)) {
            return false;
        }
    }
    return false;
}

static bool parse_value(JsonParser *parser, unsigned int depth);

static bool parse_object(JsonParser *parser, unsigned int depth)
{
    size_t count = 0;

    if (depth > MAX_JSON_DEPTH || !consume(parser, (unsigned char)'{')) {
        return false;
    }
    skip_whitespace(parser);
    if (consume(parser, (unsigned char)'}')) {
        return true;
    }
    for (;;) {
        size_t ignored_length = 0;
        if (++count > MAX_COLLECTION_ITEMS ||
            !parse_string(parser, NULL, 0, &ignored_length)) {
            return false;
        }
        skip_whitespace(parser);
        if (!consume(parser, (unsigned char)':')) {
            return false;
        }
        skip_whitespace(parser);
        if (!parse_value(parser, depth + 1U)) {
            return false;
        }
        skip_whitespace(parser);
        if (consume(parser, (unsigned char)'}')) {
            return true;
        }
        if (!consume(parser, (unsigned char)',')) {
            return false;
        }
        skip_whitespace(parser);
    }
}

static bool parse_array(JsonParser *parser, unsigned int depth)
{
    size_t count = 0;

    if (depth > MAX_JSON_DEPTH || !consume(parser, (unsigned char)'[')) {
        return false;
    }
    skip_whitespace(parser);
    if (consume(parser, (unsigned char)']')) {
        return true;
    }
    for (;;) {
        if (++count > MAX_COLLECTION_ITEMS || !parse_value(parser, depth + 1U)) {
            return false;
        }
        skip_whitespace(parser);
        if (consume(parser, (unsigned char)']')) {
            return true;
        }
        if (!consume(parser, (unsigned char)',')) {
            return false;
        }
        skip_whitespace(parser);
    }
}

static bool parse_literal(JsonParser *parser, const char *literal)
{
    size_t length = strlen(literal);
    if (parser->length - parser->cursor < length ||
        memcmp(parser->data + parser->cursor, literal, length) != 0) {
        return false;
    }
    parser->cursor += length;
    return true;
}

static bool parse_number(JsonParser *parser)
{
    size_t cursor = parser->cursor;

    if (cursor < parser->length && parser->data[cursor] == (unsigned char)'-') {
        cursor++;
    }
    if (cursor >= parser->length) {
        return false;
    }
    if (parser->data[cursor] == (unsigned char)'0') {
        cursor++;
        if (cursor < parser->length && parser->data[cursor] >= (unsigned char)'0' &&
            parser->data[cursor] <= (unsigned char)'9') {
            return false;
        }
    } else if (parser->data[cursor] >= (unsigned char)'1' &&
               parser->data[cursor] <= (unsigned char)'9') {
        do {
            cursor++;
        } while (cursor < parser->length &&
                 parser->data[cursor] >= (unsigned char)'0' &&
                 parser->data[cursor] <= (unsigned char)'9');
    } else {
        return false;
    }
    if (cursor < parser->length && parser->data[cursor] == (unsigned char)'.') {
        cursor++;
        if (cursor >= parser->length || parser->data[cursor] < (unsigned char)'0' ||
            parser->data[cursor] > (unsigned char)'9') {
            return false;
        }
        do {
            cursor++;
        } while (cursor < parser->length &&
                 parser->data[cursor] >= (unsigned char)'0' &&
                 parser->data[cursor] <= (unsigned char)'9');
    }
    if (cursor < parser->length &&
        (parser->data[cursor] == (unsigned char)'e' ||
         parser->data[cursor] == (unsigned char)'E')) {
        cursor++;
        if (cursor < parser->length &&
            (parser->data[cursor] == (unsigned char)'+' ||
             parser->data[cursor] == (unsigned char)'-')) {
            cursor++;
        }
        if (cursor >= parser->length || parser->data[cursor] < (unsigned char)'0' ||
            parser->data[cursor] > (unsigned char)'9') {
            return false;
        }
        do {
            cursor++;
        } while (cursor < parser->length &&
                 parser->data[cursor] >= (unsigned char)'0' &&
                 parser->data[cursor] <= (unsigned char)'9');
    }
    parser->cursor = cursor;
    return true;
}

static bool parse_value(JsonParser *parser, unsigned int depth)
{
    size_t ignored_length = 0;

    if (depth > MAX_JSON_DEPTH || parser->cursor >= parser->length) {
        return false;
    }
    switch (parser->data[parser->cursor]) {
    case (unsigned char)'{':
        return parse_object(parser, depth);
    case (unsigned char)'[':
        return parse_array(parser, depth);
    case (unsigned char)'"':
        return parse_string(parser, NULL, 0, &ignored_length);
    case (unsigned char)'t':
        return parse_literal(parser, "true");
    case (unsigned char)'f':
        return parse_literal(parser, "false");
    case (unsigned char)'n':
        return parse_literal(parser, "null");
    default:
        return parse_number(parser);
    }
}

static bool decoded_equals(
    const unsigned char *value,
    size_t length,
    const char *expected)
{
    size_t expected_length = strlen(expected);
    return length == expected_length && memcmp(value, expected, length) == 0;
}

static bool key_was_seen(const SeenKey *keys, size_t count, const SeenKey *candidate)
{
    size_t index;
    for (index = 0; index < count; index++) {
        if (keys[index].length == candidate->length &&
            memcmp(keys[index].data, candidate->data, candidate->length) == 0) {
            return true;
        }
    }
    return false;
}

static bool parse_required_string(
    JsonParser *parser,
    const char *expected,
    bool *observed)
{
    unsigned char value[MAX_VALUE_BYTES];
    size_t length = 0;
    if (!parse_string(parser, value, sizeof(value), &length) ||
        !decoded_equals(value, length, expected)) {
        return false;
    }
    *observed = true;
    return true;
}

static bool parse_session_start(const unsigned char *data, size_t length)
{
    JsonParser parser = {data, length, 0};
    SeenKey keys[MAX_TOP_LEVEL_KEYS];
    size_t key_count = 0;
    bool observed_event = false;
    bool observed_source = false;
    bool observed_cwd = false;

    skip_whitespace(&parser);
    if (!consume(&parser, (unsigned char)'{')) {
        return false;
    }
    skip_whitespace(&parser);
    if (consume(&parser, (unsigned char)'}')) {
        return false;
    }
    for (;;) {
        SeenKey candidate;
        if (key_count >= MAX_TOP_LEVEL_KEYS ||
            !parse_string(
                &parser,
                candidate.data,
                sizeof(candidate.data),
                &candidate.length) ||
            key_was_seen(keys, key_count, &candidate)) {
            return false;
        }
        keys[key_count++] = candidate;
        skip_whitespace(&parser);
        if (!consume(&parser, (unsigned char)':')) {
            return false;
        }
        skip_whitespace(&parser);
        if (decoded_equals(candidate.data, candidate.length, "hook_event_name")) {
            if (!parse_required_string(&parser, "SessionStart", &observed_event)) {
                return false;
            }
        } else if (decoded_equals(candidate.data, candidate.length, "source")) {
            if (!parse_required_string(&parser, "startup", &observed_source)) {
                return false;
            }
        } else if (decoded_equals(candidate.data, candidate.length, "cwd")) {
            if (!parse_required_string(
                    &parser,
                    "/runtime/critic-cwd",
                    &observed_cwd)) {
                return false;
            }
        } else if (!parse_value(&parser, 1U)) {
            return false;
        }
        skip_whitespace(&parser);
        if (consume(&parser, (unsigned char)'}')) {
            break;
        }
        if (!consume(&parser, (unsigned char)',')) {
            return false;
        }
        skip_whitespace(&parser);
    }
    skip_whitespace(&parser);
    return parser.cursor == parser.length && observed_event && observed_source && observed_cwd;
}

static const char *const sensitive_environment_names[] = {
    "ANTHROPIC_API_KEY",
    "CLAUDE_CODE_OAUTH_TOKEN",
    "ANTHROPIC_AUTH_TOKEN",
    "ANTHROPIC_FOUNDRY_API_KEY",
    "ANTHROPIC_FOUNDRY_AUTH_TOKEN",
    "ANTHROPIC_AWS_API_KEY",
    "ANTHROPIC_CUSTOM_HEADERS",
    "AWS_SECRET_ACCESS_KEY",
    "AWS_SESSION_TOKEN",
    "AWS_BEARER_TOKEN_BEDROCK",
    "GOOGLE_APPLICATION_CREDENTIALS",
    "AZURE_CLIENT_SECRET",
    "AZURE_CLIENT_CERTIFICATE_PATH",
    "ACTIONS_ID_TOKEN_REQUEST_TOKEN",
    "ACTIONS_ID_TOKEN_REQUEST_URL",
    "ACTIONS_RUNTIME_TOKEN",
    "ACTIONS_RUNTIME_URL",
    "ALL_INPUTS",
    "OVERRIDE_GITHUB_TOKEN",
    "DEFAULT_WORKFLOW_TOKEN",
    "SSH_SIGNING_KEY",
    "CLAUDE_BG_AUTH_SNAPSHOT_PATH",
    "CLAUDE_BG_SOCKET_TOKENS_PATH",
    "CLAUDE_BG_RV_AUTH",
    "CLAUDE_BG_PTY_AUTH",
};

static bool environment_is_scrubbed(void)
{
    const char *scrub = getenv("CLAUDE_CODE_SUBPROCESS_ENV_SCRUB");
    size_t index;

    if (scrub == NULL || strcmp(scrub, "1") != 0) {
        return false;
    }
    for (index = 0;
         index < sizeof(sensitive_environment_names) /
             sizeof(sensitive_environment_names[0]);
         index++) {
        const char *name = sensitive_environment_names[index];
        char input_name[128];
        size_t length = strlen(name);

        if (getenv(name) != NULL || length + sizeof("INPUT_") > sizeof(input_name)) {
            return false;
        }
        memcpy(input_name, "INPUT_", sizeof("INPUT_") - 1U);
        memcpy(input_name + sizeof("INPUT_") - 1U, name, length + 1U);
        if (getenv(input_name) != NULL) {
            return false;
        }
    }
    return true;
}

static bool read_bounded_stdin(unsigned char *buffer, size_t *length)
{
    size_t observed = 0;

    while (observed < MAX_INPUT_BYTES + 1U) {
        ssize_t count = read(
            STDIN_FILENO,
            buffer + observed,
            MAX_INPUT_BYTES + 1U - observed);
        if (count > 0) {
            observed += (size_t)count;
            continue;
        }
        if (count == 0) {
            *length = observed;
            return observed <= MAX_INPUT_BYTES;
        }
        if (errno != EINTR) {
            return false;
        }
    }
    return false;
}

static bool emit_success_marker(void)
{
    ssize_t count;
    do {
        count = write(STDERR_FILENO, success_marker, sizeof(success_marker) - 1U);
    } while (count < 0 && errno == EINTR);
    return count == (ssize_t)(sizeof(success_marker) - 1U);
}

int main(void)
{
    unsigned char input[MAX_INPUT_BYTES + 1U];
    size_t input_length = 0;

    if (!read_bounded_stdin(input, &input_length) ||
        !parse_session_start(input, input_length) ||
        !environment_is_scrubbed()) {
        return FAILURE_EXIT;
    }
    if (!emit_success_marker()) {
        return FAILURE_EXIT;
    }
    return SUCCESS_EXIT;
}
