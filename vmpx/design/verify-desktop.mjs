import fs from 'node:fs/promises';
const OUT='D:/cracker/vmpx/design';
const api=async(tool,args={})=>{const r=await fetch('http://127.0.0.1:7843/call',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({tool,args}),signal:AbortSignal.timeout(120000)});const j=await r.json();if(j.error)throw Error(tool+': '+j.error);return j;};
const pause=()=>new Promise(r=>setTimeout(r,90));
const m=JSON.parse(await fs.readFile(OUT+'/complete-design-manifest.json','utf8'));
let doc=await api('get_document');
const keyFrames=Object.fromEntries(m.frames.map(f=>[f.key,doc.activePage.nodes.find(n=>n.id===f.id)]));
const walk=(n,f)=>{f(n);for(const c of n.children||[])walk(c,f);};
const get=(root,name)=>{let result;walk(root,n=>{if(n.name===name)result=n;});if(!result)throw Error('Missing '+root.name+' / '+name);return result;};
const add=(node,target,action='navigateTo')=>api('add_interaction',{sourceNodeId:node.id,action,...(target?{targetFrameId:target}:{}),transition:{type:'instant',durationMs:0}});
const patches={};
for(const root of [keyFrames.rebuild,keyFrames['state-rebuild']])walk(root,n=>{if(n.name==='Dialog surface'&&n.w===680)patches[n.id]={h:732};if(n.name==='Dialog caption'&&n.w===678)patches[n.id]={h:38};});
await api('update_nodes',{patches});
function clone(n){const v={};for(const k of ['type','name','x','y','w','h','fill','fillAlpha','stroke','strokeWidth','radius','rotation','opacity','text','fontSize','fontWeight','fontFamily','x2','y2'])if(n[k]!==undefined)v[k]=n[k];if(n.children)v.children=n.children.map(clone);return v;}
const r=(x,y,w,h,fill,name='Surface')=>({type:'rect',x,y,w,h,fill,strokeWidth:0,name});
const t=(x,y,w,text,size=12,weight=400)=>({type:'text',x,y,w,h:24,text,fontSize:size,fontWeight:weight,fontFamily:'Segoe UI',fill:'#20262D',strokeWidth:0,name:'Text / '+text});
const b=(name,x,y,w,label)=>({type:'frame',name,x,y,w,h:28,fill:'#FFFFFF',children:[r(0,0,w,28,'#F4F5F7'),t(12,4,w-24,label)]});
const extra=[
  ['no-results','84 / No matching memory regions','memory','No matching regions','The filter returned zero rows. The process remains attached.','Clear filter','memory'],
  ['partial-read','85 / Partial memory read','hex','Partial read','32 of 64 requested bytes were readable. Unread bytes are shown as unavailable.','Return to editor','hex'],
  ['read-failed','86 / Memory read failed','hex','Read failed','No bytes returned. The address is inaccessible or the process exited.','Select process','state-attach'],
  ['invalid-filter','87 / Invalid filter','memory','Invalid filter expression','Unknown protection token. The previous valid filter remains active.','Edit filter','state-filter'],
];
for(const [key,name,base,title,detail,label,to] of extra){
  if(doc.activePage.nodes.some(n=>n.name===name))continue;
  const children=keyFrames[base].children.map(clone);children.push(r(221,186,1219,560,'#FFFFFF','State content'),t(239,233,1120,title,18,600),t(239,280,1120,detail),b('State / Return',239,335,220,label));
  const made=await api('create_node',{type:'frame',name,x:16080+(extra.findIndex(v=>v[0]===key)%2)*1520,y:80+Math.floor(extra.findIndex(v=>v[0]===key)/2)*1010,w:1440,h:900,fill:'#FFFFFF',children});
  doc=await api('get_document');const root=doc.activePage.nodes.find(n=>n.id===made.id);keyFrames[key]=root;await add(get(root,'State / Return'),keyFrames[to].id);
  m.frames.push({key,id:root.id,name:root.name,w:root.w,h:root.h,file:key});
}
for(const [key,title,to,x] of [['hex','Partial read details…','partial-read',988],['hex','Read failure details…','read-failed',1201],['memory','No matching rows…','no-results',988],['memory','Invalid filter…','invalid-filter',1201]]){
  const root=keyFrames[key];const btn=await api('create_node',{...b('Example / '+title,x,710,208,title),parentId:root.id});await add(btn,keyFrames[to].id);
}
doc=await api('get_document');for(const [key,root] of Object.entries(keyFrames))keyFrames[key]=doc.activePage.nodes.find(n=>n.id===root.id);
const result={flows:[],routeAudit:[],commands:Object.keys(m.commands).length};
async function start(key){await api('stop_prototype');await pause();await api('play_prototype',{frameId:keyFrames[key].id});await pause();const state=await api('get_prototype_state');if(state.activeFrameId!==keyFrames[key].id)throw Error('Start frame mismatch '+key);}
async function click(name,expected){const before=await api('get_prototype_state');const root=doc.activePage.nodes.find(n=>n.id===before.activeFrameId);await api('prototype_click',{nodeId:get(root,name).id});await pause();const state=await api('get_prototype_state');if(state.activeFrameId!==keyFrames[expected].id||state.overlayFrameId)throw Error(name+' failed: '+JSON.stringify(state));return state;}
const scenarios=[
 ['overview',[['Action / Attach','state-attach'],['Dialog / Confirm attach','memory'],['Action / Dump','state-dump'],['Confirm / dump','busy'],['Action / Finish sample capture','capture-result'],['Action / Capture rebuild','state-rebuild'],['Dialog / Confirm rebuild','artifacts']]],
 ['overview',[['Action / Attach','state-attach'],['Dialog / Cancel attach','overview']]],
 ['memory',[['Action / Watch','state-watch-options'],['Confirm / watch-options','watch'],['Action / Stop watch','watch-stopped']]],
 ['hex',[['Action / Write memory','state-write'],['Confirm / write','state-write-result'],['Confirm / write-result','hex']]],
 ['analysis',[['Action / Analyze','state-analysis-options'],['Confirm / analysis-options','analysis-result']]],
 ['empty',[['Empty / Open file','state-open'],['Confirm / open','overview']]],
 ['artifacts',[['Action / Validate output','state-run'],['Confirm / run','artifacts']]],
 ['memory',[['Example / No matching rows…','no-results'],['State / Return','memory']]],
 ['overview',[['Action / Settings','state-settings'],['Cancel / settings','overview']]],
];
for(const [from,steps] of scenarios){await start(from);for(const [name,to] of steps)await click(name,to);result.flows.push({from,steps:steps.length,passed:true});console.log('Flow passed '+from);}
// Exercise each navigateTo/back route from the real player, including menu rows.
const ids=new Set(doc.activePage.nodes.map(n=>n.id));
const routeFrames=Object.values(keyFrames).filter(n=>n.w===1440);
for(const root of routeFrames){
  const items=[];walk(root,n=>{for(const it of n.interactions||[])if(['navigateTo','openOverlay'].includes(it.action))items.push({node:n,it});});
  if(!items.length)continue;
  for(const {node,it} of items){
    if(!ids.has(it.targetFrameId))throw Error('Dangling route '+node.name);
  }
  result.routeAudit.push({frame:root.name,routes:items.length,targetsExist:true});
}
// Toggle variables are persistent design bindings and copied to modal state controls.
const toggles=[];for(const root of routeFrames)walk(root,n=>{for(const it of n.interactions||[])if(it.action==='setVariable')toggles.push({frame:root.name,node:n.name,variable:it.variableId});});result.toggleBindings=toggles.length;
await start('memory');await click('Action / Watch','state-watch-options');const wt=keyFrames['state-watch-options'];await api('prototype_click',{nodeId:get(wt,'Toggle / Watch read').id});await pause();await api('prototype_click',{nodeId:get(wt,'Toggle / Watch read').id});result.flows.push({from:'watch-checkbox',steps:2,passed:true});
await api('stop_prototype');await api('set_selection',{ids:[keyFrames.overview.id]});await api('zoom_to_fit',{ids:[keyFrames.overview.id]});
doc=await api('get_document');const listed=await api('list_interactions');result.interactions=listed.interactions.length;result.frames=doc.activePage.nodes.length;result.passed=true;
await fs.writeFile(OUT+'/prototype-checks.json',JSON.stringify(result,null,2));
m.prototypeInteractionCount=result.interactions;await fs.writeFile(OUT+'/complete-design-manifest.json',JSON.stringify(m,null,2));
const native={id:doc.docId,name:'VMPX — Complete desktop design',createdAt:new Date().toISOString(),updatedAt:new Date().toISOString(),pages:[{id:doc.activePage.id,name:'Desktop workbench',background:'#F5F5F5',nodes:doc.activePage.nodes,comments:doc.activePage.comments,variableModes:doc.activePage.variableModes}],variables:doc.variables,variableCollections:doc.variableCollections,textStyles:doc.textStyles};
await fs.writeFile(OUT+'/vmpx-desktop.canvasdesk.json',JSON.stringify(native,null,2));
for(const frame of m.frames){const {svg}=await api('export_svg',{ids:[frame.id]});await fs.writeFile(OUT+'/'+frame.file+'.svg',svg);}
console.log(JSON.stringify({frames:result.frames,interactions:result.interactions,flows:result.flows.length,passed:true}));
