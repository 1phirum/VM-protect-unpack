/* cmd_launch.c - armored launch */
#include "vmpx.h"
#include "util/str.h"

int cmd_launch(int argc, char** argv) {
    int armor = arg_has(argc, argv, "--no-armor") ? 0 : 1;
    int wait_ms = (int)arg_num(argc, argv, "--wait-ms", 180000);

    const char* explicit_target = arg_get(argc, argv, "--exe");
    if (!explicit_target) explicit_target = arg_get(argc, argv, "--");

    wchar_t target[MAX_PATH * 2] = { 0 };
    if (resolve_target(explicit_target, target, MAX_PATH * 2) != 0) return 1;

    wchar_t cls[128] = { 0 };
    const char* cls_arg = arg_get(argc, argv, "--class");
    if (cls_arg && *cls_arg && str_widen(cls_arg, cls, 128) != 0) return 1;

    enable_debug_privilege();
    printf("[*] target: %ls\n", target);
    return launch_armored_ex(target, armor, wait_ms, cls[0] ? cls : NULL) == 0
               ? 0 : 1;
}
