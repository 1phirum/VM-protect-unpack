/* cmd_info.c - static PE dossier */
#include "vmpx.h"

int cmd_info(int argc, char** argv) {
    const char* file = arg_get(argc, argv, "--exe");
    if (!file && argc > 2 && argv[2][0] != '-') file = argv[2];
    if (!file) {
        printf("[-] usage: vmpx info <file>\n");
        return 2;
    }

    pe_t pe;
    if (pe_load(file, &pe) != 0) return 1;
    int rc = pe_info(&pe);
    pe_free(&pe);
    return rc == 0 ? 0 : 1;
}
