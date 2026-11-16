# VM protect unpack

Qt 6 Widgets desktop interface. Actual file and process data populate the tables;
there are no seeded sample rows or simulated task completions.

Page filters and operations share one toolbar row, with an overflow menu when
the window is narrow. The sidebar identifies each page without duplicate headings.
The output panel appears when there is actual output; empty footer space is collapsed.

The 64-bit GUI uses a small read-only C inspection library and launches the existing
32-bit C command worker through QProcess for operations. The original agent remains
32-bit. Selecting a process does not inject the agent.

The GUI is organized into these modules:

- app: window composition, actions, file inspection and process/hex controllers.
- backend: C inspection boundary, asynchronous command execution and query results.
- models: reusable read-only table model.
- widgets: filtered tables and detail panes.
- dialogs: process selection and validated operation forms.
- assets: official Lucide SVGs, neutral stylesheet and preserved icon license.
- scripts: Qt dependency deployment.
- tests: real parser/process/read checks and GUI-to-worker integration.

The root CMakeLists.txt calls the GUI and build-support subdirectories. Each GUI
module has its own CMakeLists.txt. backend/CMakeLists.txt builds the existing worker
and agent under the MSVC x86 environment.

Build from D:/cracker/vmpx:

    cmake --preset windows-qt-mingw
    cmake --build --preset windows-qt-mingw
    ctest --preset windows-qt-mingw
    powershell -File gui/scripts/deploy.ps1

The preset records the Qt and compiler locations installed on this machine.
Adjust CMakePresets.json or provide your own preset for another installation.
VMPX_VCVARS32 selects the MSVC x86 environment script.

Run out/qt-release/bin/VM protect unpack.exe. Its directory must also contain
vmpx.exe, vmpxagent.dll and the deployed Qt dependencies.

Sources use the checked-in .clang-format: four-space indentation, separate blocks,
100-column limit and readable functions. Run clang-format on changed C/C++ files
before committing. CMake lists use explicit module/source names.

Offline deobf reports, captured artifacts and runtime validation stay distinct.
Tracing, handler semantics, IR lifting and native emission remain unavailable
because their backend stages are not implemented. Process permissions and agent
availability are reported from the actual backend.

Icons: https://lucide.dev — license in assets/licenses/Lucide-LICENSE.txt.

Built by Olivia — https://discord.gg/ojailbreaks
