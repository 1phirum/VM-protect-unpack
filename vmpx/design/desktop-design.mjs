import fs from 'node:fs/promises';
import path from 'node:path';

const OUT = 'D:/cracker/vmpx/design';
const api = async (tool, args = {}) => {
  const res = await fetch('http://127.0.0.1:7843/call', {
    method: 'POST', headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ tool, args }), signal: AbortSignal.timeout(30000),
  });
  if (!res.ok) throw new Error(`Bridge HTTP ${res.status}`);
  const result = await res.json();
  if (result.error) throw new Error(`${tool}: ${result.error}`);
  return result;
};
const C = { white:'#FFFFFF', canvas:'#F7F8FA', chrome:'#ECEEF0', panel:'#F4F5F7',
  border:'#CDD2D7', rule:'#E4E7EA', ink:'#20262D', muted:'#67717D', disabled:'#A0A7AF',
  accent:'#435F78', selected:'#E5EDF4', selectedInk:'#263F55', mono:'#303B46' };
const R = (x,y,w,h,fill=C.white,name='Surface',stroke=null,radius=0) =>
  ({type:'rect',x,y,w,h,fill:fill || C.white,fillAlpha:fill ? 1:0,strokeWidth:stroke ? 1:0,...(stroke?{stroke}:{}),radius,name});
const T = (x,y,w,text,size=12,fill=C.ink,weight=400,mono=false,h=20) =>
  ({type:'text',x,y,w,h,text,fontSize:size,fontWeight:weight,fontFamily:mono?'Consolas':'Segoe UI',fill,strokeWidth:0,name:`Text / ${text.split('\n')[0]}`});
const L = (x,y,dx,dy,color=C.border,width=1) =>
  ({type:'line',x,y,x2:dx,y2:dy,stroke:color,strokeWidth:width,name:'Rule'});
const G = (name,x,y,w,h,children,fill=null) => ({type:'frame',name,x,y,w,h,fill:fill || C.white,fillAlpha:fill?1:0,strokeWidth:0,children});
const icon = (kind,x,y,color=C.muted,size=18) => {
  let p;
  switch(kind) {
    case 'folder': p=[L(1,5,6,0,color),L(7,5,3,3,color),L(10,8,6,0,color),L(16,8,-1,7,color),L(15,15,-14,0,color),L(1,15,0,-10,color)];break;
    case 'attach': p=[R(3,3,12,9,null,'Process',color,1),L(9,12,0,3,color),L(5,15,8,0,color)];break;
    case 'dump': p=[L(9,1,0,10,color),L(5,7,4,4,color),L(9,11,4,-4,color),L(2,12,0,4,color),L(2,16,14,0,color),L(16,16,0,-4,color)];break;
    case 'rebuild': p=[R(3,4,12,12,null,'Image',color,1),L(6,8,6,0,color),L(6,11,6,0,color),L(6,14,3,0,color),R(7,1,4,5,C.panel,'Header',color)];break;
    case 'watch': p=[L(1,10,4,0,color),L(5,10,3,-6,color),L(8,4,3,10,color),L(11,14,3,-4,color),L(14,10,3,0,color)];break;
    case 'stop': p=[R(4,4,10,10,null,'Stop',color,1)];break;
    case 'search': p=[{type:'ellipse',x:2,y:2,w:9,h:9,fill:C.white,fillAlpha:0,stroke:color,strokeWidth:1.3},L(10,10,6,6,color,1.3)];break;
    case 'chevron': p=[L(6,4,5,5,color),L(11,9,-5,5,color)];break;
    case 'down': p=[L(4,7,5,5,color),L(9,12,5,-5,color)];break;
    case 'close': p=[L(5,5,8,8,color),L(13,5,-8,8,color)];break;
    case 'file': p=[L(4,2,7,0,color),L(11,2,4,4,color),L(15,6,0,10,color),L(15,16,-11,0,color),L(4,16,0,-14,color),L(11,2,0,4,color),L(11,6,4,0,color)];break;
    case 'check': p=[L(3,9,4,4,color,1.4),L(7,13,9,-9,color,1.4)];break;
    case 'warning': p=[L(9,1,8,15,color),L(17,16,-16,0,color),L(1,16,8,-15,color),L(9,6,0,5,color),R(8,13,2,2,color)];break;
    default:p=[R(4,4,10,10,null,'Square',color,1)];
  }
  return G(`Icon / ${kind}`,x,y,size,size,p);
};
const button = (name,x,y,w,label,kind=null,enabled=true,primary=false) => {
  const fill=primary?C.accent:C.white, color=enabled?(primary?C.white:C.ink):C.disabled;
  return G(name,x,y,w,28,[R(0,0,w,28,fill,'Button surface',primary?C.accent:C.border,3),
    ...(kind?[icon(kind,8,5,color)]:[]),T(kind?32:12,5,w-(kind?36:20),label,12,color,primary?600:400)],fill);
};
const field = (name,x,y,w,value,mono=false,kind=null) => G(name,x,y,w,30,[
  R(0,0,w,30,C.white,'Field border',C.border,2),...(kind?[icon(kind,8,6)]:[]),T(kind?32:9,6,w-35,value,12,C.ink,400,mono),
]);
const chip = (x,y,w,label) => G(`State / ${label}`,x,y,w,23,[R(0,0,w,23,C.panel,'Status border',C.border,2),T(8,3,w-12,label,11,C.muted)]);
const hex = n=>'0x'+n.toString(16).toUpperCase().padStart(8,'0');
const size = n=>n===0?'0 B':n>=1048576?(n/1048576).toFixed(1)+' MiB':n>=1024?(n/1024).toFixed(1)+' KiB':n+' B';
const targetHandle=await fs.open('D:/cracker/UnlockTool-2026-11-10-0.exe','r');
const header=Buffer.alloc(4096);await targetHandle.read(header,0,header.length,0);
const nt=header.readUInt32LE(60), secOff=nt+24+header.readUInt16LE(nt+20), sections=[];
for(let i=0;i<header.readUInt16LE(nt+6);i++) {
  const at=secOff+i*40, flags=header.readUInt32LE(at+36);
  sections.push({name:header.subarray(at,at+8).toString('latin1').replace(/\0/g,''),
    rva:header.readUInt32LE(at+12),vsize:header.readUInt32LE(at+8),raw:header.readUInt32LE(at+16),
    off:header.readUInt32LE(at+20),flags,perm:(flags&0x40000000?'R':'')+(flags&0x80000000?'W':'')+(flags&0x20000000?'X':'')});
}
const bytes=Buffer.alloc(64);await targetHandle.read(bytes,0,64,sections[11].off);await targetHandle.close();

function shell(name,x,y,active='Sections',live=false) {
  const a=[];
  a.push(R(0,0,1440,900,C.white),R(0,0,1440,32,C.chrome),R(12,8,17,17,C.accent,'VMPX mark',null,2),T(16,8,12,'V',12,C.white,600));
  a.push(T(40,7,700,'VMPX  —  UnlockTool-2026-11-10-0.exe',12,C.ink,600),L(1318,16,10,0,C.muted),R(1363,11,10,10,null,'Maximize',C.muted),icon('close',1410,7));
  a.push(R(0,32,1440,28,C.white),L(0,60,1440,0));
  ['File','Edit','View','Capture','Tools','Help'].forEach((v,i)=>a.push(T([18,60,103,149,215,263][i],37,58,v,12)));
  a.push(R(0,61,1440,43,C.panel),L(0,104,1440,0));
  a.push(button('Action / Open',12,68,102,'Open file','folder'),button('Action / Attach',122,68,98,'Attach','attach'),L(234,73,0,19));
  a.push(button('Action / Dump',250,68,94,'Dump','dump',live),button('Action / Rebuild',352,68,104,'Rebuild','rebuild',live));
  a.push(button('Action / Watch',464,68,96,'Watch','watch',live),button('Action / Stop',568,68,82,'Stop','stop',false),T(1164,74,260,live?'Attached session  ·  x86':'Static inspection  ·  x86',12,C.muted));
  a.push(R(0,105,1440,42,C.white),icon('file',14,116),T(40,116,460,'UnlockTool-2026-11-10-0.exe',12,C.ink,600));
  a.push(T(518,116,595,live?'PID 46104   |   Image base 0x00400000':'D:\\cracker\\UnlockTool-2026-11-10-0.exe',12,C.muted,400,!live),chip(1245,114,179,live?'Attached · capture ready':'File loaded · no process'));
  a.push(L(0,147,1440,0),R(0,148,220,726,C.panel),L(220,148,0,726));
  a.push(T(15,165,184,'SESSION',10,C.muted,600),icon('down',12,192, C.muted,16),icon('file',32,191),T(58,192,149,'UnlockTool',12,C.ink,600),T(58,211,148,'2026-11-10-0.exe',11,C.muted));
  const nav=['Overview','Sections','Imports','Memory','Artifacts'];
  nav.forEach((v,i)=>{const yy=248+i*32;if(v===active)a.push(R(8,yy,204,29,C.selected,'Navigation selection',null,2));a.push(T(33,yy+5,125,v,12,v===active?C.selectedInk:C.ink,v===active?600:400));if(v==='Sections')a.push(T(183,yy+5,24,'13',11,C.muted));if(v==='Imports')a.push(T(182,yy+5,27,'23',11,C.muted));});
  a.push(L(16,430,188,0,C.border),T(16,447,185,'FILE DETAILS',10,C.muted,600));
  [['Format','PE32 / x86'],['File size','214.5 MiB'],['Image size','468.1 MiB'],['Image base','0x00400000'],['Entry RVA','0x1CFD2D12']].forEach(([k,v],i)=>{a.push(T(16,473+i*30,78,k,11,C.muted),T(99,473+i*30,112,v,11,C.ink,400,i>=3));});
  a.push(L(16,637,188,0,C.border),T(16,654,190,'WORKSPACE',10,C.muted,600),icon('folder',15,679),T(41,680,163,'D:\\cracker\\vmpx',11,C.muted,400,true),T(16,720,184,live?'Process attached.\nCapture commands available.':'Attach a process for live\nmemory and capture tools.',11,C.muted,400,false,38));
  a.push(T(16,834,194,'Built by Olivia —',10,C.muted),T(16,850,194,'https://discord.gg/ojailbreaks',10,C.muted));
  a.push(R(221,148,1219,37,C.panel),L(221,185,1219,0));
  ['Sections','Imports','Memory','Artifacts'].forEach((v,i)=>{const xx=234+i*110;if(v===active){a.push(R(xx,149,106,36,C.white,'Selected tab'));a.push(L(xx,184,106,0,C.accent,2));}a.push(T(xx+14,159,92,v,12,v===active?C.ink:C.muted,v===active?600:400));});
  a.push(R(0,874,1440,26,C.chrome),L(0,874,1440,0),T(12,879,460,live?'Attached  |  PID 46104  |  x86':'Ready  |  File inspection  |  x86',11,C.muted),T(838,879,320,'Original file preserved',11,C.muted),T(1208,879,220,'VMPX  ·  Local workspace',11,C.muted));
  return {type:'frame',name,x,y,w:1440,h:900,fill:C.white,stroke:C.border,strokeWidth:1,children:a};
}
function filter(a,value,count) {a.push(field('Filter',234,194,960,value,false,'search'),T(1220,201,206,count,11,C.muted));}
function table(a,{x=221,y=233,w=1219,cols,rows,rowHeight=24,selected=-1}) {
  a.push(R(x,y,w,28,C.panel,'Table header'),L(x,y+28,w,0,C.border));
  cols.forEach(c=>a.push(T(x+c.x+12,y+6,c.w-18,c.label,11,C.muted,600)));
  rows.forEach((row,i)=>{const yy=y+28+i*rowHeight;a.push(R(x,yy,w,rowHeight,i===selected?C.selected:i%2?C.canvas:C.white,`Row ${i+1}`));cols.forEach((c,j)=>a.push(T(x+c.x+12,yy+4,c.w-18,String(row[j]),12,i===selected?C.selectedInk:C.ink,400,c.mono!==false)));});
  const bottom=y+28+rows.length*rowHeight;a.push(L(x,bottom,w,0,C.border));return bottom;
}
function logPane(a,lines,top=746) {
  a.push(R(221,top,1219,128,C.white,'Log pane'),R(221,top,1219,30,C.panel),L(221,top,1219,0),T(235,top+7,200,'Output',12,C.ink,600),T(310,top+7,200,'Session log',12,C.muted));
  a.push(T(1259,top+7,130,'Copy     Clear',11,C.muted));
  lines.forEach((s,i)=>{a.push(T(235,top+37+i*20,85,['00:00.000','00:00.041','00:00.086','00:00.112'][i]||'00:00.120',11,C.muted,400,true),T(329,top+37+i*20,1090,s,11,C.mono,400,true));});
}
function sectionsScreen(){
  const s=shell('01 / File inspection',80,80);const a=s.children;
  filter(a,'Filter sections by name, RVA or permissions…','13 sections · 1 selected');
  const cols=[{label:'#',x:0,w:42},{label:'Section',x:42,w:172},{label:'RVA',x:214,w:156},{label:'Virtual size',x:370,w:156},{label:'File offset',x:526,w:156},{label:'Raw size',x:682,w:156},{label:'Permissions',x:838,w:155,mono:false},{label:'Entropy',x:993,w:140}];
  table(a,{cols,rows:sections.map((v,i)=>[String(i+1).padStart(2,'0'),v.name,hex(v.rva),hex(v.vsize),v.off?hex(v.off):'—',v.raw?hex(v.raw):'—',v.perm,['0.000','0.000','0.000','0.000','0.000','0.000','0.000','0.000','0.000','0.000','0.933','7.990','3.719'][i]]),selected:11});
  a.push(R(221,573,1219,28,C.white),T(235,579,970,'11 virtual-only sections   ·   File-backed bytes available in 3 sections',11,C.muted));
  a.push(L(221,606,1219,0),R(221,607,1219,29,C.panel),T(235,614,570,'Section details  /  B9mFmIS0',12,C.ink,600),T(808,614,480,'File bytes  /  offset 0x00000800',12,C.ink,600),L(791,636,0,110));
  [['Address range','0x0FDA5000 – 0x1D3AFA70'],['Virtual / raw size','214.0 MiB / 214.0 MiB'],['Characteristics','Read · Execute'],['Entropy','7.990 bits / byte']].forEach(([k,v],i)=>a.push(T(239,646+i*22,174,k,11,C.muted),T(417,646+i*22,354,v,11,C.ink,400,i===0)));
  for(let i=0;i<4;i++)a.push(T(808,646+i*22,83,(0x800+i*16).toString(16).toUpperCase().padStart(8,'0'),11,C.muted,400,true),T(902,646+i*22,515,bytes.subarray(i*16,i*16+16).toString('hex').match(/../g).join(' ').toUpperCase(),11,C.mono,400,true));
  logPane(a,['Opened UnlockTool-2026-11-10-0.exe  ·  224,870,128 bytes','PE32 / x86  ·  13 sections  ·  22 import modules / 23 functions','Static inspection complete. Attach to a process to capture memory.']);return s;
}
function memoryScreen(){
  const s=shell('02 / Memory inspection',1600,80,'Memory',true);const a=s.children;
  filter(a,'type:private  state:committed','159 regions · 1 selected');
  const cols=[{label:'#',x:0,w:44},{label:'Base address',x:44,w:176},{label:'End address',x:220,w:176},{label:'Size',x:396,w:143},{label:'State',x:539,w:145,mono:false},{label:'Type',x:684,w:143,mono:false},{label:'Protect',x:827,w:145},{label:'Mapped module',x:972,w:230,mono:false}];
  const rows=[['01','0x1D818000','0x1D819000','4 KiB','Committed','Private','RW','—'],['02','0x1D890000','0x1D8D0000','256 KiB','Committed','Private','RW','—'],['03','0x1DA00000','0x1DB00000','1 MiB','Committed','Private','RX','—'],['04','0x1DB00000','0x1DD00000','2 MiB','Committed','Private','RW','—'],['05','0x1DF00000','0x1E000000','1 MiB','Committed','Private','RW','—'],['06','0x20000000','0x21000000','16 MiB','Committed','Private','RW','—'],['07','0x22000000','0x23000000','16 MiB','Committed','Private','RW','—'],['08','0x24100000','0x24120000','128 KiB','Committed','Private','RW','—'],['09','0x25000000','0x25010000','64 KiB','Committed','Private','RW','—'],['10','0x26000000','0x26040000','256 KiB','Committed','Private','RW','—'],['11','0x2A000000','0x2A100000','1 MiB','Committed','Private','RX','—'],['12','0x2A200000','0x2A300000','1 MiB','Committed','Private','RW','—'],['13','0x2B000000','0x2B020000','128 KiB','Committed','Private','RW','—']];
  table(a,{cols,rows,selected:3});
  a.push(T(235,579,1050,'Private committed 55.0 MiB   ·   Image 468.1 MiB   ·   Address range 0x00000000 – 0x80000000',11,C.muted));
  a.push(L(221,606,1219,0),R(221,607,1219,29,C.panel),T(235,614,540,'Region details  /  0x1DB00000',12,C.ink,600),T(809,614,440,'Capture',12,C.ink,600),L(791,636,0,110));
  [['Base / size','0x1DB00000 / 2 MiB'],['State / type','Committed / Private'],['Protection','Read · Write'],['Allocation','0x1DB00000']].forEach(([k,v],i)=>a.push(T(239,646+i*22,174,k,11,C.muted),T(417,646+i*22,354,v,11,C.ink,400,i===0||i===3)));
  a.push(T(809,647,510,'Capture the mapped image and private regions separately.',11,C.muted),button('Action / Save snapshot',809,676,162,'Save snapshot','dump'),button('Action / Capture image',982,676,157,'Capture image','dump'),T(809,713,510,'Output: D:\\cracker\\vmpx\\artifacts\\session',11,C.muted,400,true));
  logPane(a,['Attached to PID 46104  ·  x86  ·  image base 0x00400000','Agent attached  ·  status mapping available','Memory map collected. Private regions ready for capture.']);return s;
}
function resultScreen(){
  const s=shell('03 / Reconstruction result',80,1090,'Artifacts',false);const a=s.children;
  filter(a,'Filter artifacts by name or result…','4 artifacts');
  const cols=[{label:'Artifact',x:0,w:280,mono:false},{label:'Type',x:280,w:170,mono:false},{label:'Size',x:450,w:170},{label:'Created',x:620,w:220},{label:'Validation',x:840,w:335,mono:false}];
  table(a,{cols,rows:[['live.bin','Image dump','468.1 MiB','2026-11-14 23:20','Captured'],['live.bin.meta','Metadata','157 B','2026-11-14 23:20','Recorded'],['snap.bin','Private regions','55.0 MiB','2026-11-14 23:35','Captured'],['rebuilt-oep-clean.exe','PE image','468.1 MiB','2026-11-14 23:20','Runtime validation failed']],selected:3,rowHeight:32});
  a.push(R(235,418,1188,38,C.panel,'Validation summary',C.border,2),icon('warning',247,429,C.muted),T(276,428,1108,'File created. Runtime validation failed; the process exited before opening a window.',12,C.ink,600));
  a.push(T(237,478,1100,'Reconstruction report',13,C.ink,600));
  [['Output','rebuilt-oep-clean.exe'],['Private regions','141 restored / 18 failed'],['Module resolution','Unavailable in the recorded run'],['Process startup','Created; subsequently exited'],['Login window','Not observed'],['Result','Partial restore · runtime validation failed']].forEach(([k,v],i)=>{const yy=512+i*31;a.push(T(237,yy,215,k,12,C.muted),T(464,yy,760,v,12,C.ink,400,k==='Output'),L(237,yy+26,1178,0,C.rule));});
  a.push(button('Action / Open output folder',237,710,172,'Open output folder','folder'),button('Action / View run log',420,710,139,'View run log','file'),T(602,717,802,'A produced file and a verified runnable image are separate results.',11,C.muted));
  logPane(a,['Snapshot restore: 141 regions mapped; 18 regions failed.','Process created. Runtime validation: process exited.','No login window observed. Retain the original executable.']);return s;
}
function attachDialog(){
  const a=[R(0,0,640,448,C.white,'Dialog surface',C.border,3),R(1,1,638,38,C.chrome,'Dialog caption'),T(16,10,561,'Attach to process',13,C.ink,600),icon('close',609,10),T(20,59,592,'Select the running target for memory inspection and capture.',12,C.muted),field('Process filter',20,92,600,'UnlockTool',false,'search')];
  table(a,{x:20,y:140,w:600,cols:[{label:'Process',x:0,w:335,mono:false},{label:'PID',x:335,w:100},{label:'Architecture',x:435,w:164,mono:false}],rows:[['UnlockTool-2026-11-10-0.exe','46104','x86'],['explorer.exe','4280','x64'],['notepad.exe','19872','x64']],rowHeight:31,selected:0});
  a.push(T(20,278,599,'Selected: UnlockTool-2026-11-10-0.exe',12,C.ink,600),T(20,304,596,'x86 target  ·  Compatible with the x86 agent',12,C.muted),L(20,349,600,0,C.rule),T(20,367,321,'Attach enables live inspection tools.',11,C.muted),button('Dialog / Cancel attach',427,371,91,'Cancel'),button('Dialog / Confirm attach',529,371,91,'Attach',null,true,true));
  return {type:'frame',name:'04 / Attach dialog',x:1600,y:1090,w:640,h:448,fill:C.white,strokeWidth:0,children:a};
}
function rebuildDialog(){
  const a=[R(0,0,680,564,C.white,'Dialog surface',C.border,3),R(1,1,678,38,C.chrome,'Dialog caption'),T(16,10,589,'Rebuild PE image',13,C.ink,600),icon('close',649,10),T(20,57,640,'Reconstruct an image from a capture and its original headers.',12,C.muted)];
  [['Original executable','D:\\cracker\\UnlockTool-2026-11-10-0.exe'],['Image capture','artifacts\\session\\live.bin'],['Output image','artifacts\\session\\rebuilt.exe']].forEach(([k,v],i)=>{a.push(T(20,93+i*71,629,k,11,C.muted,600),field('Input / '+k,20,115+i*71,593,v,true),button('Browse / '+k,622,115+i*71,38,'…'));});
  a.push(L(20,331,640,0,C.rule),T(20,346,640,'Import recovery',12,C.ink,600),T(20,371,640,'Resolve the import table from the attached process.',12,C.muted),chip(20,400,183,'PID 46104 · x86 target'),T(235,405,411,'Live process required',11,C.muted));
  a.push(R(20,445,14,14,null,'Clean data checkbox',C.border,1),T(43,443,619,'Restore writable data from the original file',12,C.ink),T(43,467,603,'Advanced entry-point settings remain optional.',11,C.muted),L(20,501,640,0,C.rule),button('Dialog / Cancel rebuild',453,518,91,'Cancel'),button('Dialog / Confirm rebuild',555,518,105,'Rebuild',null,true,true));
  return {type:'frame',name:'05 / Rebuild dialog',x:1600,y:1630,w:680,h:564,fill:C.white,strokeWidth:0,children:a};
}
await fs.mkdir(OUT,{recursive:true});
const original=await api('get_document');
const builds=[sectionsScreen(),memoryScreen(),resultScreen(),attachDialog(),rebuildDialog()];
const created=[];
for(const spec of builds){const result=await api('create_node',spec);created.push(result);console.log(`Created ${result.name}: ${result.id}`);}
const document=await api('get_document');
const get=(root,name)=>{let result=null;const visit=n=>{if(n.name===name)result=n;for(const c of n.children||[])visit(c);};visit(root);if(!result)throw Error(`Missing ${name}`);return result;};
const roots=created.map(v=>document.activePage.nodes.find(n=>n.id===v.id));
const interactions=[
  [0,'Action / Attach',3,'openOverlay'],[1,'Action / Rebuild',4,'openOverlay'],
  [3,'Dialog / Confirm attach',1,'navigateTo'],[3,'Dialog / Cancel attach',null,'closeOverlay'],
  [4,'Dialog / Confirm rebuild',2,'navigateTo'],[4,'Dialog / Cancel rebuild',null,'closeOverlay'],
];
for(const [src,name,dst,action] of interactions) await api('add_interaction',{sourceNodeId:get(roots[src],name).id,...(dst!==null?{targetFrameId:roots[dst].id}:{}),action,transition:{type:'instant',durationMs:0}});
for(let i=0;i<3;i++)for(const [label,dst] of [['Sections',0],['Memory',1],['Artifacts',2]]){
  if(i===dst)continue;
  const root=roots[i];
  const textNodes=[];const visit=n=>{if(n.type==='text'&&n.text===label)textNodes.push(n);for(const c of n.children||[])visit(c);};visit(root);
  for(const n of textNodes)await api('add_interaction',{sourceNodeId:n.id,targetFrameId:roots[dst].id,action:'navigateTo',transition:{type:'instant',durationMs:0}});
}
await api('set_flow_start',{frameId:roots[0].id,on:true,name:'VMPX / Desktop inspection'});
await api('set_selection',{ids:[roots[0].id]});
const final=await api('get_document');
const native={id:final.docId,name:'VMPX — Desktop workspace',createdAt:new Date().toISOString(),updatedAt:new Date().toISOString(),pages:[{id:final.activePage.id,name:'Desktop workspace',background:'#F5F5F5',nodes:final.activePage.nodes,comments:final.activePage.comments,variableModes:final.activePage.variableModes}],variables:final.variables,variableCollections:final.variableCollections,textStyles:final.textStyles};
await fs.writeFile(path.join(OUT,'vmpx-desktop.canvasdesk.json'),JSON.stringify(native,null,2));
await fs.writeFile(path.join(OUT,'design-manifest.json'),JSON.stringify({docId:final.docId,pageId:final.activePage.id,frames:created,originalNodeCount:original.activePage.nodes.length,colors:C,dimensions:{desktop:[1440,900],attach:[640,448],rebuild:[680,564]}},null,2));
for(let i=0;i<roots.length;i++){const {svg}=await api('export_svg',{ids:[roots[i].id]});await fs.writeFile(path.join(OUT,['01-file-inspection.svg','02-memory-inspection.svg','03-reconstruction-result.svg','04-attach-dialog.svg','05-rebuild-dialog.svg'][i]),svg);}
console.log(JSON.stringify({document:final.docId,page:final.activePage.id,frames:created.length,output:OUT}));
