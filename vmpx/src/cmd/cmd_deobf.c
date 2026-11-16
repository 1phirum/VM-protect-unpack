/* cmd_deobf.c - fully dynamic deobfuscation driver
 *
 * The old static dump analyzer is not called here. The command attaches to a
 * running process, injects the collector agent when needed, enables the live
 * techniques, and writes their artifact folders.
 */
#include "vmpx.h"
#include "unpack/deobf/dynamic/report/report.h"

int cmd_deobf(int argc, char** argv) {
    return dyn_report_run(argc, argv);
}
