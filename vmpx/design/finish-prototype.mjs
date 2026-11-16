import fs from 'node:fs/promises';
const OUT='D:/cracker/vmpx/design';
const api=async(tool,args={})=>{const r=await fetch('http://127.0.0.1:7843/call',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({tool,args}),signal:AbortSignal.timeout(120000)});const j=await r.json();if(j.error)throw Error(tool+': '+j.error);return j;};
const manifest=JSON.parse(await fs.readFile(OUT+'/complete-design-manifest.json','utf8'));
let doc=await api('get_document');
if(doc.activePage.nodes.some(n=>n.name==='52 / Attach / Desktop state'))throw Error('Modal states already created.');
const frames=Object.fromEntries(manifest.frames.map(f=>[f.key,doc.activePage.nodes.find(n=>n.id===f.id)]));
const walk=(n,f)=>{f(n);for(const c of n.children||[])walk(c,f);};
const rect=(x,y,w,h,fill,name='Surface',alpha=1)=>({type:'rect',x,y,w,h,fill,fillAlpha:alpha,strokeWidth:0,name});
const text=(x,y,w,value)=>({type:'text',name:'Text / '+value,x,y,w,h:20,text:value,fontFamily:'Segoe UI',fontSize:12,fontWeight:400,fill:'#20262D',strokeWidth:0});
// Fix sidebar active selection in every workspace.
const active={sections:'Sections',memory:'Memory',artifacts:'Artifacts',overview:'Overview',imports:'Imports',liveimports:'Imports',modules:'Modules',hex:'Hex editor','hex-read':'Hex editor',windows:'Windows',agent:'Agent',watch:'Watch','watch-stopped':'Watch',analysis:'Analysis','analysis-result':'Analysis',log:'Session log',empty:'Overview',busy:'Memory','capture-result':'Artifacts'};
const patches={};
for(const [key,root] of Object.entries(frames))if(active[key])walk(root,n=>{
  if(n.name.startsWith('Nav / ')){const selected=n.name.slice(6)===active[key];patches[n.children[0].id]={fill:selected?'#E5EDF4':'#F4F5F7'};patches[n.children[1].id]={fill:selected?'#263F55':'#20262D',fontWeight:selected?600:400};}
  if(n.type==='text'&&n.text==='Copy     Clear')patches[n.id]={text:'Copy / export…'};
});
for(const [key,root] of Object.entries(frames)){
  if(key==='imports')walk(root,n=>{if(n.type==='text'&&n.text==='IAT RVA')patches[n.id]={text:'RVA (illustrative)'};});
  if(key==='empty')walk(root,n=>{if(n.type==='text'&&n.text==='Static inspection  ·  x86')patches[n.id]={text:'No target selected'};});
}
await api('update_nodes',{patches});doc=await api('get_document');for(const key of Object.keys(frames))frames[key]=doc.activePage.nodes.find(n=>n.id===frames[key].id);
const bindingPairs=[];
function clone(n){const copy={};for(const k of ['type','name','x','y','w','h','fill','fillAlpha','stroke','strokeWidth','radius','rotation','opacity','text','fontSize','fontWeight','fontFamily','fontStyle','x2','y2','points','src'])if(n[k]!==undefined)copy[k]=n[k];if(n.children)copy.children=n.children.map(clone);return copy;}
const origins={attach:'overview',rebuild:'memory',open:'empty',launch:'overview',inject:'modules',dump:'memory',snapshot:'memory',oep:'memory',write:'hex','write-result':'hex','watch-options':'memory',run:'artifacts','analysis-options':'analysis','import-options':'imports',settings:'overview',error:'memory','attach-incompatible':'overview','cancel-task':'busy','clear-log':'log',export:'log','export-result':'log',browse:'overview',about:'overview',shortcuts:'overview',filter:'memory','memory-options':'memory','file-menu':'overview','edit-menu':'hex','view-menu':'overview','capture-menu':'memory','tools-menu':'memory','help-menu':'overview'};
const states={};let num=52;
for(const [key,origin] of Object.entries(origins)){
  const dialog=frames[key],parent=frames[origin];
  const background=parent.children.map(clone);const modal=clone(dialog);
  const menu=key.endsWith('-menu');modal.x=menu?({ 'file-menu':12,'edit-menu':54,'view-menu':96,'capture-menu':143,'tools-menu':210,'help-menu':254}[key]):Math.round((1440-dialog.w)/2);modal.y=menu?61:Math.round((900-dialog.h)/2);modal.name='Modal / '+key;
  const spec={type:'frame',name:`${num++} / ${key==='attach'?'Attach':key} / Desktop state`,x:9760+(Object.keys(states).length%4)*1520,y:80+Math.floor(Object.keys(states).length/4)*1010,w:1440,h:900,fill:'#FFFFFF',children:[...background,...(menu?[]:[rect(0,32,1440,868,'#20262D','Modal dimmer',0.22)]),modal]};
  const result=await api('create_node',spec);states[key]={id:result.id,origin,dialogId:dialog.id};console.log('Desktop modal '+key);
}
doc=await api('get_document');
const nodeById=new Map();for(const root of doc.activePage.nodes)walk(root,n=>nodeById.set(n.id,n));
const lookup=name=>Object.values(frames).find(n=>n.id===name);
const add=async(node,to,action='navigateTo',extra={})=>api('add_interaction',{sourceNodeId:node.id,action,...(to?{targetFrameId:to}:{}),transition:{type:'instant',durationMs:0},...extra});
function pair(a,b,fn){fn(a,b);for(let i=0;i<(a.children||[]).length;i++)pair(a.children[i],b.children[i],fn);}
for(const [key,state] of Object.entries(states)){
  const root=doc.activePage.nodes.find(n=>n.id===state.id),modal=root.children.at(-1),source=frames[key];
  const tasks=[];
  pair(source,modal,(old,n)=>{
    for(const [property,variableId] of Object.entries(old.variableBindings||{}))tasks.push(()=>api('variable_command',{command:{kind:'bind',pageId:doc.activePage.id,ids:[n.id],property,variableId}}));
    for(const it of old.interactions||[]){
      let to=it.targetFrameId,action=it.action;
      if(action==='openOverlay'){const dest=Object.entries(frames).find(([,f])=>f.id===to)?.[0];if(states[dest])to=states[dest].id;action='navigateTo';}
      if(action==='closeOverlay'){action='back';to=null;}
      tasks.push(()=>add(n,to,action,...(action==='setVariable'?[{variableId:it.variableId,variableOperation:it.variableOperation}]:[])));
    }
  });
  for(const task of tasks)await task();
  // Close native file pickers and notices back to their invoking state.
  if(['browse','settings','export-result','about','shortcuts'].includes(key)){
    const buttons=[];walk(modal,n=>{if(n.name==='Confirm / '+key)buttons.push(n);});
    for(const n of buttons){const stale=[];walk(source,o=>{if(o.name===n.name)for(const it of o.interactions||[])stale.push(it);});if(!stale.length)await add(n,null,'back');}
  }
}
// Route actual desktop actions into modal stage states; avoid overlay-only navigation.
for(const root of doc.activePage.nodes){
  if(Object.values(states).some(s=>s.id===root.id))continue;
  const items=[];walk(root,n=>{for(const it of n.interactions||[])if(it.action==='openOverlay')items.push({node:n,it});});
  for(const {node,it} of items){const dest=Object.entries(frames).find(([,f])=>f.id===it.targetFrameId)?.[0];if(states[dest])await api('update_interaction',{sourceNodeId:node.id,interactionId:it.id,patch:{action:'navigateTo',targetFrameId:states[dest].id}});}
  if(root.w===1440){
    const copies=[];walk(root,n=>{if(n.type==='text'&&n.text==='Copy / export…')copies.push(n);});for(const n of copies)await add(n,states.export.id);
  }
}
// Focus, sample empty-filter result and error demonstrations are reachable.
for(const [key,label,to] of [['memory','Read error details…','error'],['agent','Agent unavailable…','error']]){
  const root=frames[key];const btn=await api('create_node',{type:'frame',parentId:root.id,name:'Action / '+label,x:1090,y:710,w:326,h:28,fill:'#FFFFFF',children:[rect(0,0,326,28,'#F4F5F7'),text(12,5,300,label)]});await add(btn,states[to].id);
}
await api('set_selection',{ids:[frames.overview.id]});
await api('zoom_to_fit',{ids:[frames.overview.id]});
doc=await api('get_document');
for(const [key,state] of Object.entries(states)){const n=doc.activePage.nodes.find(n=>n.id===state.id);manifest.frames.push({key:'state-'+key,id:n.id,name:n.name,w:n.w,h:n.h,file:'state-'+key});}
manifest.modalStates=states;
const listed=await api('list_interactions');manifest.prototypeInteractionCount=listed.interactions?.length??listed.count;
await fs.writeFile(OUT+'/complete-design-manifest.json',JSON.stringify(manifest,null,2));
const native={id:doc.docId,name:'VMPX — Complete desktop design',createdAt:new Date().toISOString(),updatedAt:new Date().toISOString(),pages:[{id:doc.activePage.id,name:'Desktop workbench',background:'#F5F5F5',nodes:doc.activePage.nodes,comments:doc.activePage.comments,variableModes:doc.activePage.variableModes}],variables:doc.variables,variableCollections:doc.variableCollections,textStyles:doc.textStyles};
await fs.writeFile(OUT+'/vmpx-desktop.canvasdesk.json',JSON.stringify(native,null,2));
for(const frame of manifest.frames){const {svg}=await api('export_svg',{ids:[frame.id]});await fs.writeFile(OUT+'/'+frame.file+'.svg',svg);}
console.log(JSON.stringify({frames:manifest.frames.length,modalStates:Object.keys(states).length,interactions:manifest.prototypeInteractionCount}));
