/*
 * format_demo.c
 *
 * C companion to secure_input/templates.py.
 * Shows the two classic C input handling bugs:
 *   1. format string vulnerability - printf(user_input)
 *   2. stack buffer overflow       - strcpy into a fixed size buffer
 * and the safe replacements for each.
 *
 * Build:  gcc -Wall -o format_demo format_demo.c
 *         (gcc will warn about the unsafe printf - that is the point)
 * Run:    ./format_demo "Patient %x %x %x %x"
 */

#include <stdio.h>
#include <string.h>

#define NAME_SIZE 16

/* UNSAFE: user input is used as the format string */
void unsafe_print(const char *user_input)
{
    printf(user_input);
    printf("\n");
}

/* SAFE: format string is a constant, user input is only an argument */
void safe_print(const char *user_input)
{
    printf("%s\n", user_input);
}

/* UNSAFE: strcpy does not know how big 'name' is */
void unsafe_copy(const char *user_input)
{
    char name[NAME_SIZE];
    strcpy(name, user_input);   /* overflows if input is 16 chars or more */
    printf("unsafe copy: %s\n", name);
}

/* SAFE: snprintf never writes more than sizeof(name) bytes and always
 * null terminates the result */
void safe_copy(const char *user_input)
{
    char name[NAME_SIZE];
    snprintf(name, sizeof(name), "%s", user_input);
    if (strlen(user_input) >= sizeof(name)) {
        printf("input was truncated to %zu chars\n", sizeof(name) - 1);
    }
    printf("safe copy:   %s\n", name);
}

int main(int argc, char *argv[])
{
    const char *input = (argc > 1) ? argv[1] : "Patient %x %x %x %x";

    printf("--- format string ---\n");
    printf("unsafe: ");
    unsafe_print(input);
    printf("safe:   ");
    safe_print(input);

    printf("\n--- buffer copy ---\n");
    safe_copy(input);

    /* Only call the unsafe copy with short input so the demo does not crash.
     * Remove the check to see the overflow (stack smashing detected / segfault). */
    if (strlen(input) < NAME_SIZE) {
        unsafe_copy(input);
    } else {
        printf("unsafe copy skipped: input is %zu bytes, buffer is %d\n",
               strlen(input), NAME_SIZE);
    }

    return 0;
}
