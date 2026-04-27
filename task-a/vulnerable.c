/*
 * Secret question auth — vulnerable build. Deliberate overflow: gets() has no
 * size check; long input can corrupt the stack (auth flag / return address).
 * Build: gcc -m32 -g -fno-stack-protector -z execstack -o vulnerable vulnerable.c
 */

#include <stdio.h>
#include <string.h>

#define INPUT_SIZE 16

static const char storedAnswer[] = "Onimisi";

void verifyUser(void) {
    char userInput[INPUT_SIZE]; /* answer typed by user; fixed 16B on stack */
    int authenticated = 0;      /* 0 = denied, 1 = ok — sits after buffer, overflow can flip it */

    printf("=====================================\n");
    printf(" Secret Question Verification Utility\n");
    printf("=====================================\n");

    printf("Question:\n");
    printf("What is your childhood best friend's name?\n\n");

    printf("Enter answer: ");

    gets(userInput); /* bad: unbounded read — can write past userInput */

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
