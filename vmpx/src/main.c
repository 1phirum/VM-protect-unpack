/* main.c - command dispatcher only. All logic lives in src/cmd and below. */
#include "vmpx.h"

typedef int (*cmd_fn)(int argc, char** argv);

typedef struct {
    const char* name;
    cmd_fn      fn;
    const char* usage;
} cmd_t;

static const cmd_t CMDS[] = {
    { "info",        cmd_info,        "info <file>" },
    { "imports",     cmd_imports,     "imports <file> [--limit N]" },
    { "launch",      cmd_launch,      "launch [--no-armor] [--wait-ms N] [--class name] [--exe <path> | -- <exe>]" },
    { "modules",     cmd_modules,     "modules [--pid N | --name exe] [--filter name]" },
    { "inject",      cmd_inject,      "inject [--pid N | --name exe] --dll <path>" },
    { "dump",        cmd_dump,        "dump [--pid N | --name exe] [--out file] [--max-mb N]" },
    { "liveimports", cmd_liveimports, "liveimports [--pid N | --name exe] [--limit N]" },
    { "agentstatus", cmd_agentstatus, "agentstatus [--pid N | --name exe]" },
    { "peek",        cmd_peek,        "peek [--pid N | --name exe] --addr 0xADDR [--size N]" },
    { "poke",        cmd_poke,        "poke [--pid N | --name exe] --addr 0xADDR --bytes \"90 90\"" },
    { "rebuild",     cmd_rebuild,     "rebuild --live <dump> --out <pe> [--file <original.exe>] [--pid N] [--cast]" },
    { "windows",     cmd_windows,     "windows [--pid N | --name exe]" },
    { "memmap",      cmd_memmap,      "memmap [--pid N] [--near 0xADDR] [--radius N] [--all] [--private] [--min-kb N]" },
    { "oep",         cmd_oep,         "oep [--pid N | --name exe | --launch] [--wait-ms N] [--out file]" },
    { "oepcap",      cmd_oepcap,      "oepcap --exe <target.exe> --out <snapshot> [--lo 0x10000] [--oep-rva 0x1234]" },
    { "snap",        cmd_snap,        "snap [--pid N | --name exe] --out <snapshot> [--all-private]" },
    { "run",         cmd_run,         "run --snap <snapshot> --exe <rebuilt.exe>" },
    { "deobf",       cmd_deobf,       "deobf [--pid N | --name exe] --out <dir> [--seconds N] [--mode meta] [--mem-ms N] [--thread-ms N] [--addr 0xADDR --size N] [--no-strings]" },
    { "watch",       cmd_watch,       "watch [--pid N | --name exe] [--addr 0xADDR --size N] [--mode rwx] [--seconds N] [--out file] [--capture dir]" },
};

static void usage(void) {
    printf("vmpx - PE / live-process toolkit for protected binaries\n\n");
    for (size_t i = 0; i < sizeof(CMDS) / sizeof(CMDS[0]); i++)
        printf("  vmpx %s\n", CMDS[i].usage);
    printf("\nTarget resolution: --exe <path>, $VMPX_TARGET, or the single .exe in the "
           "current directory.\n");
}

int main(int argc, char** argv) {
    /* QProcess pipes need each watch/status line immediately. */
    setvbuf(stdout, NULL, _IONBF, 0);
    setvbuf(stderr, NULL, _IONBF, 0);
    if (argc < 2) { usage(); return 2; }

    for (size_t i = 0; i < sizeof(CMDS) / sizeof(CMDS[0]); i++) {
        if (strcmp(argv[1], CMDS[i].name) == 0)
            return CMDS[i].fn(argc, argv);
    }

    printf("[-] unknown command: %s\n\n", argv[1]);
    usage();
    return 2;
}
