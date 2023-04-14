#include "std_testcase.h"
#include <wchar.h>
#include <unistd.h>
#include <fcntl.h>
#include <dlfcn.h>

void CWE114_Process_Control__w32_char_file_01_bad() {
    char *data;
    char buffer[100] = "";
    int file_descriptor;
    ssize_t nread;

    file_descriptor = open("/tmp/file.txt", O_RDONLY);

    if (file_descriptor == -1) {
        printf("Cannot open file\n");
        return;
    }

    do {
        nread = read(file_descriptor, buffer, sizeof(buffer));
        if (nread == 0)
            break;

    } while (nread != 0);

    close(file_descriptor);

    data = buffer;

    char *allowed_dir = "/usr/lib/";
    if (strncmp(data, allowed_dir, strlen(allowed_dir)) != 0) {
        return;
    }

    void *handle = dlopen(data, RTLD_NOW);
    if (handle != NULL) {
        dlclose(handle);
        printf("Library loaded and freed successfully\n");
    } else {
        printf("Unable to load library\n");
    }
}

static void goodG2B() {
    char *data;
    char data_buffer[100] = "";
    data = data_buffer;
    strcpy(data, "/usr/lib/libc.so.6");

    void *handle = dlopen(data, RTLD_NOW);
    if (handle != NULL) {
        dlclose(handle);
        printf("Library loaded and freed successfully\n");
    } else {
        printf("Unable to load library\n");
    }
}

void CWE114_Process_Control_w32_char_file_01_good() {
    goodG2B();
}

int main(int argc, char *argv[]) {
    srand((unsigned) time(NULL));
    printf("Calling good()...\n");
    CWE114_Process_Control_w32_char_file_01_good();
    printf("Finished good()\n");

    printf("Calling bad()...\n");
    CWE114_Process_Control__w32_char_file_01_bad();
    printf("Finished bad()\n");
    return 0;
}

