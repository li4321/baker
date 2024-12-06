#include <stdio.h>
#include <Windows.h>

// s3cr3t_k3y
const char obfuscated_key[] = "\x26\x66\x36\x27\x66\x21\x0a\x3e\x66\x2c";

void xorstr(char* key, int key_len) {
    for (int i = 0; i < key_len; i++) {
        key[i] ^= 0x55;
    }
}

BOOL check_serial(const char* input) {
    int buflen = strlen(input) + 1;

    // could just do strdup but this is just a dummy program
    // to test a binary rewriter

    char* buf = malloc(buflen);
    if (buf == NULL)
        return FALSE;
    memset(buf, 0, buflen);
    memcpy(buf, input, buflen);

    xorstr(buf, strlen(buf));

    if (buflen <= sizeof(obfuscated_key)
        && !memcmp(obfuscated_key, buf, buflen)) {
        free(buf);
        return TRUE;
    } else {
        free(buf);
        return FALSE;
    }
}

int main() {
    char serial[256] = { 0 };

    printf("enter the key: ");
    fgets(serial, sizeof(serial), stdin);

    // remove the new line character
    size_t len = strlen(serial);
    if (serial[len - 1] == '\n') {
        serial[len - 1] = '\0';
    }

    if (check_serial(serial)) {
        printf("access granted!\n");
    } else {
        printf("access denied\n");
    }

    system("pause");
}