Built by Olivia — https://discord.gg/ojailbreaks

# VMPX desktop design

Editable Canvasdesk desktop workbench: 87 frames, 962 prototype interactions,
coverage for the 18 existing CLI commands, native menus, dialogs and task states.
Palette: neutral white/gray, restrained blue-gray selections. Typography:
Segoe UI and Consolas. Desktop frames are 1440 × 900.

Open the flow **VMPX / Complete desktop** in the connected Canvasdesk document.
The overview frame is selected. **VMPX / Start empty** is a second entry point.

`vmpx-desktop.canvasdesk.json` is the complete editable scene backup.
`complete-design-manifest.json` maps frame IDs, command coverage, interactions,
input examples and palette values. `complete-desktop-overview.png` presents
sixteen representative screens. Individual frames are exported as SVG and PNG.

The prototype links navigation, menus, dialogs, cancellation, checkboxes,
representative edited field values and representative table-row selection.
Input examples switch on click; arbitrary text entry requires implementation
in the native application. Process reads, writes, launches and captures are
not connected to the CLI in this design deliverable.

Live-process values and successful completion states are illustrative.
The reconstruction report retains the recorded failed runtime result:
141 restored regions, 18 failures, process exit, no observed login window.
Offline analysis is represented by the existing `deobf` command. VM tracing,
handler semantics, IR lifting and native emission remain planned backend work.

Verification: `prototype-checks.json`, `final-prototype-checks.json`,
`control-bindings.json` and `visual-checks.json`.

Authoring scripts mutate the connected document. Do not rerun creation scripts
against the finished design; they are delivery records and fail or duplicate
existing content. `export-final.mjs` safely refreshes SVGs at exact frame sizes.
`render-previews.cjs` renders the exported SVGs through Electron with hidden
windows. `contact-sheet.py` assembles the overview PNG from rendered previews.
