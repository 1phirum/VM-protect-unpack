import fs from 'node:fs/promises';
const OUT='D:/cracker/vmpx/design';
const api=async(tool,args={})=>{const r=await fetch('http://127.0.0.1:7843/call',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({tool,args}),signal:AbortSignal.timeout(120000)});const j=await r.json();if(j.error)throw Error(tool+': '+j.error);return j;};
const m=JSON.parse(await fs.readFile(OUT+'/complete-design-manifest.json','utf8'));let doc=await api('get_document');
const walk=(n,f)=>{f(n);for(const c of n.children||[])walk(c,f);};
const items=[];for(const root of doc.activePage.nodes)walk(root,n=>items.push({root,n}));
const patches={};
for(const {root,n} of items){
 if(root.w===1440&&n.type==='text'&&/^VMPX  —  \d+ \//.test(n.text))patches[n.id]={text:'VMPX  —  UnlockTool-2026-11-10-0.exe'};
 if(root.w<1000&&n.type==='text'&&/^\d+ \//.test(n.text))patches[n.id]={text:n.text.replace(/^\d+ \/ /,'')};
 if(n.type==='text'&&['Open 1','Open 2','Open 3','Open 4'].includes(n.text))patches[n.id]={text:({'Open 1':'Inspect sections','Open 2':'Attach process…','Open 3':'Capture image…','Open 4':'Rebuild image…'}[n.text])};
}
await api('update_nodes',{patches});
// Native prototype input fields use click-to-cycle representative valid values.
const groups=new Map();
for(const {root,n} of items)if(n.type==='frame'&&n.name.startsWith('Input / ')&&!n.interactions?.length){const label=n.name.slice(8);const txt=n.children.find(c=>c.type==='text');if(!txt)continue;if(!groups.has(label))groups.set(label,[]);groups.get(label).push({root,n,txt});}
const alternatives={Address:['0x1DB00000','0x1DA00000'],'Read size':['64','128'],'Watch address':['0x1DB00000','0x1DA00000'],'Watch size':['64','4096'],'Watch duration':['10','30'],'Max MB':['600','1024'],'Launch wait':['180000','60000'],'OEP wait':['0','5000'],'Import limit':['300','600'],'Rebuild base':['Auto / captured base','0x00400000'],'Rebuild entry':['Auto / original entry','0x1CFD2D12'],'Write address':['0x1DB00010','0x1DB00020'],'Write bytes':['90 90','90 90 90 90'],'Near':['0x1DB00000','0x1DA00000'],'Radius':['1048576','2097152'],'Minimum KB':['64','128'],'Snapshot lower':['0x1D800000','0x00000001'],'Settings max':['600','1024']};
const controlBindings=[];let idx=0;
for(const [label,fields] of groups){
 const original=fields[0].txt.text;const options=alternatives[label]||[original,original.includes('session')?original.replace('session','session-02'):original+' '];
 const collectionId='vmpx-input-'+(++idx),variableId=collectionId+'-value';
 await api('variable_command',{command:{kind:'createCollection',id:collectionId,name:'Inputs / '+label}});
 await api('variable_command',{command:{kind:'createVariable',variable:{id:variableId,name:label,type:'string',value:options[0],collectionId}}});
 let v=await api('list_variables',{collectionId,limit:10});const defaultMode=v.collections[0].modes[0].id;
 await api('variable_command',{command:{kind:'addMode',collectionId,name:'Edited example',id:collectionId+'-edited'}});
 await api('variable_command',{command:{kind:'setValue',id:variableId,modeId:collectionId+'-edited',value:options[1]}});
 for(const {n,txt} of fields){
  await api('variable_command',{command:{kind:'bind',pageId:doc.activePage.id,ids:[txt.id],property:'text',variableId}});
  await api('add_interaction',{sourceNodeId:n.id,action:'setVariableMode',variableCollectionId:collectionId,variableModeId:collectionId+'-edited',transition:{type:'instant',durationMs:0}});
 }
 controlBindings.push({label,fields:fields.length,collectionId,defaultMode,editedMode:collectionId+'-edited',examples:options});
}
// Each table row visibly updates its own selection state without changing source data.
let tables=0,rowInteractions=0;
for(const root of doc.activePage.nodes){
 const rows=[];walk(root,n=>{if(n.type==='rect'&&/^Row \d+$/.test(n.name))rows.push(n);});if(!rows.length)continue;
 const collectionId='vmpx-rows-'+(++tables);await api('variable_command',{command:{kind:'createCollection',id:collectionId,name:'Rows / '+root.name}});
 const colors=[];for(let i=0;i<rows.length;i++){const variableId=collectionId+'-'+i;await api('variable_command',{command:{kind:'createVariable',variable:{id:variableId,name:'Row '+(i+1),type:'color',value:rows[i].fill,collectionId}}});await api('variable_command',{command:{kind:'bind',pageId:doc.activePage.id,ids:[rows[i].id],property:'fill',variableId}});colors.push(variableId);}
 for(let i=0;i<rows.length;i++){
  const modeId=collectionId+'-select-'+i;await api('variable_command',{command:{kind:'addMode',collectionId,name:'Row '+(i+1),id:modeId}});
  for(let j=0;j<rows.length;j++)await api('variable_command',{command:{kind:'setValue',id:colors[j],modeId,value:{type:'solid',color:i===j?'#E5EDF4':j%2?'#F7F8FA':'#FFFFFF',alpha:1}}});
  await api('add_interaction',{sourceNodeId:rows[i].id,action:'setVariableMode',variableCollectionId:collectionId,variableModeId:modeId,transition:{type:'instant',durationMs:0}});rowInteractions++;
 }
}
doc=await api('get_document');const listed=await api('list_interactions');m.prototypeInteractionCount=listed.interactions.length;m.inputExamples=controlBindings;m.rowSelectionInteractions=rowInteractions;
await fs.writeFile(OUT+'/complete-design-manifest.json',JSON.stringify(m,null,2));
const native={id:doc.docId,name:'VMPX — Complete desktop design',createdAt:new Date().toISOString(),updatedAt:new Date().toISOString(),pages:[{id:doc.activePage.id,name:'Desktop workbench',background:'#F5F5F5',nodes:doc.activePage.nodes,comments:doc.activePage.comments,variableModes:doc.activePage.variableModes}],variables:doc.variables,variableCollections:doc.variableCollections,textStyles:doc.textStyles};
await fs.writeFile(OUT+'/vmpx-desktop.canvasdesk.json',JSON.stringify(native,null,2));
await fs.writeFile(OUT+'/control-bindings.json',JSON.stringify({inputExamples:controlBindings,rowSelectionInteractions:rowInteractions,note:'Fields demonstrate edited values in the prototype; production text entry requires native UI implementation.'},null,2));
for(const frame of m.frames){const {svg}=await api('export_svg',{ids:[frame.id]});await fs.writeFile(OUT+'/'+frame.file+'.svg',svg);}
console.log(JSON.stringify({frames:m.frames.length,interactions:m.prototypeInteractionCount,inputGroups:controlBindings.length,rowInteractions}));
