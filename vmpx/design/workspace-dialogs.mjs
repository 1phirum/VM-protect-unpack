// Native desktop dialogs; all actions are design/prototype actions.
export function buildDialogs(h) {
  const {C,R,T,L,G,icon,button,field}=h;
  const routes=[];
  const link=(node,to,action='navigateTo')=>{routes.push({name:node.name,to,action});return node;};
  const B=(name,x,y,w,label,to,action='navigateTo',primary=false)=>link(button(name,x,y,w,label,null,true,primary),to,action);
  const dialogs=[];
  function dialog(key,title,sub,w=680,height=550){
    const a=[R(0,0,w,height,C.white,'Dialog surface',C.border,3),R(1,1,w-2,38,C.chrome,'Dialog caption'),T(16,10,w-62,title,13,C.ink,600),link(icon('close',w-31,10),null,'closeOverlay'),T(20,57,w-40,sub,12,C.muted)];
    const spec={key,type:'frame',name:title,x:0,y:0,w,h:height,fill:C.white,children:a};dialogs.push(spec);return spec;
  }
  function input(s,name,label,value,y,w=s.w-80){s.children.push(T(20,y,s.w-40,label,11,C.muted,600),field('Input / '+name,20,y+22,w,value,/0x|\\|\.exe|\.bin/.test(value)),B('Browse / '+name,s.w-51,y+22,31,'…','browse','openOverlay'));}
  function check(s,name,label,y,on=true){const mark=icon('check',0,1,C.accent,14);mark.name='Checkmark / '+name;const toggle=G('Toggle / '+name,20,y,s.w-40,24,[R(0,3,14,14,C.white,'Checkbox',C.border,1),mark,T(24,1,s.w-72,label,12,C.ink)]);toggle.initialChecked=on;s.children.push(toggle);}
  function footer(s,label,to,action='navigateTo'){const y=s.h-49;s.children.push(L(20,y-16,s.w-40,0,C.rule),B('Cancel / '+s.key,s.w-222,y,90,'Cancel',null,'closeOverlay'),B('Confirm / '+s.key,s.w-121,y,101,label,to,action,true));}
  function note(s,text,y){s.children.push(R(20,y,s.w-40,41,C.panel,'Dialog note',C.border,2),T(31,y+9,s.w-62,text,11,C.muted));}
  let s=dialog('open','22 / Open executable','Select an original PE32 executable to inspect.',740,402);
  input(s,'Executable','Executable','D:\\cracker\\UnlockTool-2026-11-10-0.exe',99);
  s.children.push(T(20,184,700,'Detected format',11,C.muted,600),T(20,210,700,'PE32 / x86  ·  224,870,128 bytes  ·  13 sections',12,C.ink));note(s,'Open reads file metadata. A process is selected separately for live tools.',266);footer(s,'Open','overview');
  s=dialog('launch','23 / Launch target','Start the executable and wait for the agent bootstrap.',740,492);
  input(s,'Launch executable','Executable','D:\\cracker\\UnlockTool-2026-11-10-0.exe',99);
  check(s,'Launch armor','Enable armor / suspended agent bootstrap',183,true);
  s.children.push(T(20,233,310,'Wait timeout (milliseconds)',11,C.muted,600),field('Input / Launch wait',20,256,220,'180000',true),T(256,263,463,'Default: 180,000 ms',11,C.muted));note(s,'Timeout and process exit are task errors with retained command output.',328);footer(s,'Launch','memory');
  s=dialog('inject','24 / Load agent DLL','Load a compatible DLL into the selected process.',740,446);
  s.children.push(T(20,100,700,'Target',11,C.muted,600),T(20,126,700,'UnlockTool-2026-11-10-0.exe  ·  PID 46104  ·  x86',12,C.ink));input(s,'Agent DLL','DLL path','D:\\cracker\\vmpx\\vmpxagent.dll',174);note(s,'The application checks target and DLL architecture before starting the task.',280);footer(s,'Load DLL','agent');
  s=dialog('dump','25 / Capture mapped image','Read the mapped image into an output file.',740,535);
  input(s,'Dump output','Output image','artifacts\\session\\live.bin',99);
  s.children.push(T(20,187,700,'Maximum capture size (MiB)',11,C.muted,600),field('Input / Max MB',20,211,220,'600',true),T(256,218,460,'Estimated image: 468.1 MiB',11,C.muted));
  check(s,'Force dump','Allow a partial capture if commitment validation fails',275,false);note(s,'Default: incomplete commitment stops capture. Partial results are marked explicitly.',336);footer(s,'Capture','busy');
  s=dialog('snapshot','26 / Save private-memory snapshot','Capture private regions separately from the mapped image.',740,543);
  input(s,'Snapshot output','Output snapshot','artifacts\\session\\snap.bin',99);
  s.children.push(T(20,187,700,'Lower address bound',11,C.muted,600),field('Input / Snapshot lower',20,211,260,'0x1D800000',true));check(s,'All private','Include all private memory regions',267,false);note(s,'Snapshot metadata records each region and its protection for later restore.',338);footer(s,'Save','capture-result');
  s=dialog('oep','27 / Entry-point capture','Collect candidate entry-point evidence and save a capture.',740,565);
  input(s,'OEP output','Output capture','artifacts\\session\\oep.bin',99);check(s,'OEP launch','Launch the target before collecting',184,false);
  s.children.push(T(20,233,700,'Wait before collection (milliseconds)',11,C.muted,600),field('Input / OEP wait',20,257,260,'0',true),T(20,311,700,'Candidate evidence',12,C.ink,600),T(20,339,700,'Entry candidates remain unverified until reconstruction and execution checks.',12,C.muted));note(s,'Capture output does not prove the candidate is the original entry point.',405);footer(s,'Capture','busy');
  s=dialog('write','28 / Write process memory','Review the selected address and replacement bytes.',740,493);
  input(s,'Write address','Address','0x1DB00010',99,700);input(s,'Write bytes','Replacement bytes (hex)','90 90',181,700);
  s.children.push(T(20,267,700,'Current bytes',11,C.muted,600),T(20,292,700,'74 12  ·  2 bytes  ·  read-write region',12,C.ink,400,true));note(s,'Apply writes two bytes in the attached process; the source executable is preserved.',343);footer(s,'Apply','write-result','openOverlay');
  s=dialog('write-result','29 / Memory write result','Illustrative result: replacement bytes were written.',590,357);
  s.children.push(T(20,108,550,'Address    0x1DB00010',12,C.ink,400,true),T(20,143,550,'Written    2 / 2 bytes',12,C.ink,400,true),T(20,178,550,'Read-back  90 90',12,C.ink,400,true));footer(s,'Done','hex');
  s=dialog('watch-options','30 / Configure memory watch','Select a range, access types, duration and output.',740,674);
  s.children.push(T(20,99,700,'Address / size',11,C.muted,600),field('Input / Watch address',20,121,342,'0x1DB00000',true),field('Input / Watch size',375,121,345,'64',true));
  check(s,'Watch read','Read accesses',173,true);check(s,'Watch write','Write accesses',202,true);check(s,'Watch execute','Execute accesses',231,true);
  s.children.push(T(20,279,700,'Duration (seconds)',11,C.muted,600),field('Input / Watch duration',20,302,220,'10',true));input(s,'Watch output','Event output','artifacts\\session\\watch.csv',354);input(s,'Watch capture','Capture directory (optional)','artifacts\\session\\watch',433);check(s,'Watch once','Stop after the first matching event',520,false);footer(s,'Start','watch');
  s=dialog('run','31 / Validate reconstructed image','Restore a snapshot and inspect the reconstructed process result.',740,474);
  input(s,'Run exe','Reconstructed executable','artifacts\\session\\rebuilt-oep-clean.exe',99);input(s,'Run snapshot','Private-memory snapshot','artifacts\\session\\snap.bin',181);note(s,'Recorded result: 141 regions restored / 18 failed; process exited.',288);footer(s,'Run','artifacts');
  s=dialog('analysis-options','32 / Configure offline analysis','Select a captured image and output directory.',740,562);
  input(s,'Analysis live','Image capture','artifacts\\session\\live.bin',99);input(s,'Analysis original','Original executable (optional)','D:\\cracker\\UnlockTool-2026-11-10-0.exe',179);input(s,'Analysis output','Report directory','artifacts\\session\\analysis',259);check(s,'Analysis strings','Include string analysis',349,true);note(s,'Offline analysis produces reports. VM lifting and native emission remain planned.',407);footer(s,'Analyze','analysis-result');
  s=dialog('import-options','33 / Import inspection options','Configure static or runtime import collection.',620,440);
  s.children.push(T(20,105,580,'Function limit',11,C.muted,600),field('Input / Import limit',20,130,220,'300',true));check(s,'Import cast','Use reverse-resolved IAT scan during rebuild',188,false);note(s,'Static default: 200. Live default: 300. Recovery requires a running process.',266);footer(s,'Apply','liveimports');
  s=dialog('settings','34 / Workspace settings','Desktop defaults for this local workspace.',740,594);
  s.children.push(T(20,101,700,'Appearance',12,C.ink,600),T(20,132,700,'System light  ·  Segoe UI 12 px  ·  Consolas for addresses and bytes',12,C.muted));check(s,'Compact rows','Compact table rows',173,true);check(s,'Output pane','Show output pane',204,true);check(s,'Session log','Retain command output in session log',235,true);
  input(s,'Settings output','Default artifact directory','D:\\cracker\\vmpx\\artifacts',291);s.children.push(T(20,382,700,'Capture read limit (MiB)',11,C.muted,600),field('Input / Settings max',20,406,220,'600',true));note(s,'Shortcuts: Ctrl+O open · Ctrl+F filter · Ctrl+, settings · Esc dismiss dialog',474);footer(s,'Save',null,'closeOverlay');
  s=dialog('error','35 / Process operation failed','The selected process could not be opened.',660,438);
  s.children.push(T(20,105,620,'Access denied  ·  Win32 error 5',13,C.ink,600),T(20,145,620,'Check the process access level and whether the target is still running.',12,C.muted),T(20,189,620,'No capture or write was completed. Command output remains in the log.',12,C.muted));note(s,'Other task errors use this layout: process exit, incompatible architecture or invalid input.',259);footer(s,'Select PID','attach','openOverlay');
  s=dialog('attach-incompatible','36 / Incompatible process','The selected process is x64. The current agent is x86.',640,359);
  s.children.push(T(20,111,600,'explorer.exe  ·  PID 4280  ·  x64',12,C.ink,600),T(20,155,600,'Choose an x86 target or configure a compatible build.',12,C.muted));footer(s,'Choose PID','attach','openOverlay');
  s=dialog('cancel-task','37 / Cancel capture','Stop the current read and discard the incomplete output?',610,320);
  s.children.push(T(20,106,570,'Incomplete file: live.bin.part',12,C.ink,400,true),T(20,146,570,'Completed artifacts and previous captures remain available.',12,C.muted));footer(s,'Stop','memory');
  s=dialog('clear-log','38 / Clear visible output','Clear the visible output pane?',610,319);
  s.children.push(T(20,107,570,'Retained command output stays in the session log.',12,C.muted));footer(s,'Clear','log');
  s=dialog('export','39 / Export session output','Choose the log destination.',740,345);
  input(s,'Export file','Log file','artifacts\\session\\session-log.txt',99);footer(s,'Export','export-result','openOverlay');
  s=dialog('export-result','40 / Export complete','Illustrative result: the session log was saved.',600,292);
  s.children.push(T(20,111,560,'artifacts\\session\\session-log.txt',12,C.ink,400,true));footer(s,'Done',null,'closeOverlay');
  s=dialog('browse','41 / Select local file','Native file-selection design for input and output paths.',740,442);
  s.children.push(field('Input / Browse path',20,99,700,'D:\\cracker\\vmpx\\artifacts',true),R(20,149,700,32,C.panel),T(32,157,420,'Name',11,C.muted,600),T(545,157,155,'Type',11,C.muted,600));
  [['session','Folder'],['live.bin','Binary capture'],['snap.bin','Snapshot'],['rebuilt.exe','Executable']].forEach(([n,t],i)=>s.children.push(R(20,181+i*29,700,29,i===1?C.selected:i%2?C.canvas:C.white),T(32,187+i*29,490,n,12,C.ink),T(545,187+i*29,155,t,11,C.muted)));footer(s,'Select',null,'closeOverlay');
  s=dialog('about','42 / About VMPX','Windows PE and live-process desktop workbench.',680,440);
  s.children.push(T(20,107,640,'VMPX',22,C.ink,600),T(20,148,640,'Desktop UI design / editable Canvasdesk prototype',12,C.muted),T(20,188,640,'x86 command backend · 18 existing commands',12,C.ink),T(20,231,640,'Built by Olivia — https://discord.gg/ojailbreaks',12,C.muted));footer(s,'Close',null,'closeOverlay');
  s=dialog('shortcuts','43 / Keyboard shortcuts','Desktop keyboard reference.',680,495);
  [['Ctrl+O','Open executable'],['Ctrl+F','Focus current table filter'],['Ctrl+,','Workspace settings'],['Esc','Dismiss dialog'],['F5','Refresh current inspection'],['Ctrl+Shift+S','Save session output'],['Ctrl+L','Show session log']].forEach(([k,v],i)=>s.children.push(T(20,101+i*35,205,k,12,C.ink,400,true),T(244,101+i*35,416,v,12,C.muted)));footer(s,'Close',null,'closeOverlay');
  s=dialog('filter','44 / Filter table','Filter rows by text, address, type or protection.',680,402);
  input(s,'Filter expression','Expression','type:private state:committed',99,640);s.children.push(T(20,185,640,'Examples: kernel32 · 0x00400000 · protect:RX · state:committed',12,C.muted));note(s,'Clear the expression to restore the table. Invalid syntax keeps the previous filter.',253);footer(s,'Apply','memory');
  s=dialog('memory-options','45 / Memory map options','Configure the region query.',680,526);
  s.children.push(T(20,99,640,'Near address / radius (bytes)',11,C.muted,600),field('Input / Near',20,124,309,'0x1DB00000',true),field('Input / Radius',343,124,317,'1048576',true),T(20,186,640,'Minimum region size (KiB)',11,C.muted,600),field('Input / Minimum KB',20,209,220,'64',true));check(s,'Private regions','Private regions only',268,true);check(s,'All regions','Include all region types and states',301,false);note(s,'Address-relative queries and private-only queries follow the command options.',378);footer(s,'Apply','memory');
  const menus=[
    ['file-menu','46 / File menu',[['Open executable…','Ctrl+O','open','openOverlay'],['Launch target…','','launch','openOverlay'],['Attach to process…','','attach','openOverlay'],['Export session output…','Ctrl+Shift+S','export','openOverlay'],['Close target','','empty','navigateTo']]],
    ['edit-menu','47 / Edit menu',[['Filter rows…','Ctrl+F','filter','openOverlay'],['Read memory…','','hex','navigateTo'],['Write memory…','','write','openOverlay'],['Workspace settings…','Ctrl+,','settings','openOverlay']]],
    ['view-menu','48 / View menu',[['Target overview','','overview','navigateTo'],['Sections','','sections','navigateTo'],['Imports','','imports','navigateTo'],['Modules','','modules','navigateTo'],['Memory map','','memory','navigateTo'],['Hex editor','','hex','navigateTo'],['Windows','','windows','navigateTo'],['Session log','Ctrl+L','log','navigateTo']]],
    ['capture-menu','49 / Capture menu',[['Capture mapped image…','','dump','openOverlay'],['Save private snapshot…','','snapshot','openOverlay'],['Entry-point capture…','','oep','openOverlay'],['Configure watch…','','watch-options','openOverlay'],['Stop watch','','watch-stopped','navigateTo']]],
    ['tools-menu','50 / Tools menu',[['Agent status','','agent','navigateTo'],['Load agent DLL…','','inject','openOverlay'],['Live imports','','liveimports','navigateTo'],['Rebuild PE image…','','rebuild','openOverlay'],['Validate reconstructed image…','','run','openOverlay'],['Offline analysis…','','analysis-options','openOverlay']]],
    ['help-menu','51 / Help menu',[['Keyboard shortcuts','','shortcuts','openOverlay'],['About VMPX','','about','openOverlay']]],
  ];
  for(const [key,title,items] of menus){const w=370,height=items.length*32+18,children=[R(0,0,w,height,C.white,'Menu surface',C.border,2)];items.forEach(([label,shortcut,to,action],i)=>children.push(link(G('Menu / '+label,5,8+i*32,w-10,31,[R(0,0,w-10,31,i===0?C.selected:C.white),T(12,6,255,label,12,C.ink),T(262,6,89,shortcut,11,C.muted)]),to,action)));dialogs.push({key,type:'frame',name:title,x:0,y:0,w,h:height,fill:C.white,children});}
  return {dialogs,routes};
}
