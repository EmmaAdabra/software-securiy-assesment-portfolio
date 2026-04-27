/*
 * Same programme as vulnerable.c, but gets() replaced with fgets() so input
 * cannot exceed the buffer. Build: gcc -o fixed fixed.c
 */

#include <stdio.h>
#include <string.h>

#define INPUT_SIZE 16

static const char storedAnswer[] = "Onimisi";

void verifyUser(void) {
    char userInput[INPUT_SIZE]; /* answer buffer; size passed to fgets so reads stay inside */
    int authenticated = 0;     /* 0/1; can't be overwritten by a long string anymore */

    printf("=====================================\n");
    printf(" Secret Question Verification Utility\n");
    printf("=====================================\n");

    printf("Question:\n");
    printf("What is your childhood best friend's name?\n\n");

    printf("Enter answer: ");

    /* fgets: reads at most sizeof(userInput)-1 chars + null; excess stays in stdin, no overflow */
    if (fgets(userInput, sizeof(userInput), stdin) != NULL) {
        size_t len = strlen(userInput);
        if (len > 0 && userInput[len - 1] == '\n') {
            userInput[len - 1] = '\0'; /* strip newline or strcmp won't match "Onimisi" */
        }
    }

    if (strcmp(userInput, storedAnswer) == 0) {
        authenticated = 1;
    }

    printf("\nAuthentication status: %d\n", authenticated);

    if (authenticated) {
        printf("Access Granted: Secret notes unlocked.\n");
    } else {
        printf("Access Denied.\n");
    }
}

int main(void) {
    verifyUser();
    return 0;
}
