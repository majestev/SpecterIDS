#include "common.h"

#include <ctype.h>
#include <stdio.h>
#include <string.h>

const char *ids_severity_name(ids_severity_t severity)
{
    switch (severity) {
    case IDS_SEVERITY_LOW:
        return "LOW";
    case IDS_SEVERITY_MEDIUM:
        return "MEDIUM";
    case IDS_SEVERITY_HIGH:
        return "HIGH";
    case IDS_SEVERITY_CRITICAL:
        return "CRITICAL";
    case IDS_SEVERITY_COUNT:
    default:
        return "UNKNOWN";
    }
}

static int ascii_casecmp(const char *left, const char *right)
{
    unsigned char a;
    unsigned char b;

    if (left == NULL || right == NULL) {
        return left == right ? 0 : 1;
    }

    while (*left != '\0' && *right != '\0') {
        a = (unsigned char)tolower((unsigned char)*left);
        b = (unsigned char)tolower((unsigned char)*right);
        if (a != b) {
            return (int)a - (int)b;
        }
        left++;
        right++;
    }

    return (int)(unsigned char)tolower((unsigned char)*left) -
           (int)(unsigned char)tolower((unsigned char)*right);
}

bool ids_parse_severity(const char *value, ids_severity_t *out)
{
    if (value == NULL || out == NULL) {
        return false;
    }

    if (ascii_casecmp(value, "LOW") == 0) {
        *out = IDS_SEVERITY_LOW;
        return true;
    }
    if (ascii_casecmp(value, "MEDIUM") == 0) {
        *out = IDS_SEVERITY_MEDIUM;
        return true;
    }
    if (ascii_casecmp(value, "HIGH") == 0) {
        *out = IDS_SEVERITY_HIGH;
        return true;
    }
    if (ascii_casecmp(value, "CRITICAL") == 0) {
        *out = IDS_SEVERITY_CRITICAL;
        return true;
    }

    return false;
}

bool ids_parse_bool(const char *value, bool *out)
{
    if (value == NULL || out == NULL) {
        return false;
    }

    if (ascii_casecmp(value, "true") == 0 ||
        ascii_casecmp(value, "yes") == 0 ||
        ascii_casecmp(value, "on") == 0 ||
        strcmp(value, "1") == 0) {
        *out = true;
        return true;
    }

    if (ascii_casecmp(value, "false") == 0 ||
        ascii_casecmp(value, "no") == 0 ||
        ascii_casecmp(value, "off") == 0 ||
        strcmp(value, "0") == 0) {
        *out = false;
        return true;
    }

    return false;
}

void ids_copy_string(char *dst, size_t dst_size, const char *src)
{
    if (dst == NULL || dst_size == 0) {
        return;
    }

    if (src == NULL) {
        dst[0] = '\0';
        return;
    }

    snprintf(dst, dst_size, "%s", src);
}

char *ids_trim(char *value)
{
    char *end;

    if (value == NULL) {
        return NULL;
    }

    while (*value != '\0' && isspace((unsigned char)*value)) {
        value++;
    }

    if (*value == '\0') {
        return value;
    }

    end = value + strlen(value) - 1;
    while (end > value && isspace((unsigned char)*end)) {
        *end = '\0';
        end--;
    }

    return value;
}
