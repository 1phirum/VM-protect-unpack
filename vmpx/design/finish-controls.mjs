import fs from 'node:fs/promises';
const OUT='D:/cracker/vmpx/design';
const api=async(tool,args={})=>{const r=await fetch('http://127.0.0.1:7843/call',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({tool,args}),signal:AbortSignal.timeout(120000)});const j=await r.json();if(j.error)throw Error(tool+': '+j.error);return j;};
const m=JSON.parse(await fs.readFile(OUT+'/complete-design-manifest.json','utf8'));let doc=await api('get_document');
const walk=(n,f)=>{f(n);for(const c of n.children||[])walk(c,f);};
const add=(node,target,action='navigateTo',extra={})=>api('add_interaction',{sourceNodeId:node.id,action,...(target?{targetFrameId:target}:{}),transition:{type:'instant',durationMs:0},...extra});
const templates=new Map();for(const n of doc.activePage.nodes)if(n.w===1440&&!n.name.includes('Desktop state'))walk(n,c=>{if(c.type==='rect'&&/^Row \d+$/.test(c.name)&&c.variableBindings?.fill)templates.set(c.id,c);});
const vars=await api('list_variables',{limit:500});const rowCollection=vars.collections.find(c=>c.name==='Rows / 01 / File inspection');
if(rowCollection){const modes=rowCollection.modes;const last=modes.at(-1);if(last.name==='Row 1'){
 const rows=vars.variables.filter(v=>v.collectionId===rowCollection.id);for(let i=0;i<rows.length;i++)await api('variable_command',{command:{kind:'setValue',id:rows[i].id,modeId:last.id,value:{type:'solid',color:i===0?'#E5EDF4':i%2?'#F7F8FA':'#FFFFFF',alpha:1}}});
 const first=[...templates.values()][0];if(first&&!first.interactions?.length)await add(first,null,'setVariableMode',{variableCollectionId:rowCollection.id,variableModeId:last.id});
 }}
// Color modes demonstrate selecting and clearing a row with bounded shared bindings.
await api('variable_command',{command:{kind:'createCollection',id:'vmpx-row-selection',name:'Table row selection'}});
await api('variable_command',{command:{kind:'createVariable',variable:{id:'vmpx-row-color',name:'Row fill',type:'color',value:'#FFFFFF',collectionId:'vmpx-row-selection'}}});
await api('variable_command',{command:{kind:'addMode',collectionId:'vmpx-row-selection',name:'Selected',id:'vmpx-row-selected'}});
await api('variable_command',{command:{kind:'setValue',id:'vmpx-row-color',modeId:'vmpx-row-selected',value:{type:'solid',color:'#E5EDF4',alpha:1}}});
let selections=0;
for(const root of doc.activePage.nodes){if(root.w!==1440||root.name.includes('Desktop state'))continue;const rows=[];walk(root,n=>{if(n.type==='rect'&&/^Row \d+$/.test(n.name))rows.push(n);});
 // One representative unbound row per workspace supplies visible interaction feedback.
 const row=rows.find(n=>!n.variableBindings?.fill);if(!row)continue;
 await api('variable_command',{command:{kind:'bind',pageId:doc.activePage.id,ids:[row.id],property:'fill',variableId:'vmpx-row-color'}});
 await add(row,null,'setVariableMode',{variableCollectionId:'vmpx-row-selection',variableModeId:'vmpx-row-selected'});selections++;
}
// Preserve incompatible architecture row navigation above table selection hotspots.
doc=await api('get_document');const attachState=doc.activePage.nodes.find(n=>n.name==='52 / Attach / Desktop state');let incompatible;walk(attachState,n=>{if(n.name==='Attach / Incompatible row')incompatible=n;});if(incompatible)await api('update_nodes',{patches:{[incompatible.id]:{fillAlpha:0}}});
const nodes=new Map();for(const root of doc.activePage.nodes)walk(root,n=>nodes.set(n.id,n));
const inputVariables=(await api('list_variables',{limit:500})).collections.filter(c=>c.name.startsWith('Inputs / '));
m.inputExamples=inputVariables.map(c=>({name:c.name,modes:c.modes}));m.rowSelectionInteractions=selections;
doc=await api('get_document');const listed=await api('list_interactions');m.prototypeInteractionCount=listed.interactions.length;
await fs.writeFile(OUT+'/complete-design-manifest.json',JSON.stringify(m,null,2));
await fs.writeFile(OUT+'/control-bindings.json',JSON.stringify({inputExamples:m.inputExamples,rowSelectionExamples:selections,limitation:'Prototype fields switch to representative edited values. Native text entry and process operations require application implementation.'},null,2));
const native={id:doc.docId,name:'VMPX — Complete desktop design',createdAt:new Date().toISOString(),updatedAt:new Date().toISOString(),pages:[{id:doc.activePage.id,name:'Desktop workbench',background:'#F5F5F5',nodes:doc.activePage.nodes,comments:doc.activePage.comments,variableModes:doc.activePage.variableModes}],variables:doc.variables,variableCollections:doc.variableCollections,textStyles:doc.textStyles};
await fs.writeFile(OUT+'/vmpx-desktop.canvasdesk.json',JSON.stringify(native,null,2));
for(const frame of m.frames){const {svg}=await api('export_svg',{ids:[frame.id]});await fs.writeFile(OUT+'/'+frame.file+'.svg',svg);}
console.log(JSON.stringify({frames:m.frames.length,interactions:m.prototypeInteractionCount,inputGroups:m.inputExamples.length,selectionExamples:selections}));
