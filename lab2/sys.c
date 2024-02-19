#include <unistd.h>
#include <stdio.h>

int main() {
    long max_pass_len;

    // Get the maximum password length
    max_pass_len = sysconf(_SC_PASS_MAX);

    if (max_pass_len == -1) {
        // Handling error or the value is not limited
        perror("sysconf");
        // It might be appropriate to handle this case differently
        // since -1 might also mean that the system does not have a limit
    } else {
        printf("Maximum password length: %ld\n", max_pass_len);
    }

    return 0;
}

