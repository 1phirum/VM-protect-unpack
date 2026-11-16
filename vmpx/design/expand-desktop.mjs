import fs from 'node:fs/promises';
import vm from 'node:vm';
import {buildWorkspaces} from './workspace-screens.mjs';
import {buildDialogs} from './workspace-dialogs.mjs';

const OUT='D:/cracker/vmpx/design';
const call=async(tool,args={})=>{
  const r=await fetch('http://127.0.0.1:7843/call',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({tool,args}),signal:AbortSignal.timeout(120000)});
  const j=await r.json();if(j.error)throw Error(tool+': '+j.error);return j;
};
const base=await fs.readFile(OUT+'/desktop-design.mjs','utf8');
const prelude=base.slice(base.indexOf('const C ='),base.indexOf('const targetHandle'));
const helpers=base.slice(base.indexOf('function table('),base.indexOf('function sectionsScreen'));
const ctx=vm.createContext({});vm.runInContext(prelude+'\n'+helpers+'\nglobalThis.h={C,R,T,L,G,icon,button,field,chip,table,logPane};',ctx);
const h=ctx.h,{C,R,T,L,G,icon,button,field}=h;
const {screens,routes:screenRoutes,nav}=buildWorkspaces(h),{dialogs,routes:dialogRoutes}=buildDialogs(h);
const routes=[...screenRoutes,...dialogRoutes];
const original=await call('get_document');
await fs.writeFile(OUT+'/before-expansion.canvasdesk.json',JSON.stringify(original,null,2));
const existing=original.activePage.nodes;
const roots={sections:existing.find(n=>n.id==='1:0cou4i5kk'),memory:existing.find(n=>n.id==='1:rnckif5to'),artifacts:existing.find(n=>n.id==='1:rltjyj5xi'),attach:existing.find(n=>n.id==='1:ywrcwe60y'),rebuild:existing.find(n=>n.id==='1:zw4k7w627')};
if(Object.values(roots).some(n=>!n))throw Error('Original five frames missing; no mutation performed.');
const priorNames=new Set(existing.map(n=>n.name));
if(screens.some(s=>priorNames.has(s.name)))throw Error('Expanded frames already exist. Refusing duplicate authoring.');
const walk=(n,f)=>{f(n);for(const c of n.children||[])walk(c,f);};
const byName=(root,name)=>{let found;walk(root,n=>{if(n.name===name)found=n;});return found;};
const adds=async(root,spec)=>call('create_node',{...spec,parentId:root.id});
// Replace the short sidebar in the original workspaces with the complete navigation.
for(const [key,root] of Object.entries(roots)){
  if(['attach','rebuild'].includes(key))continue;
  const side=screens[0].children.filter(n=>(n.x<220&&n.y>=244&&n.y<814)&&n.name!=='Surface');
  const full=[R(0,244,220,580,C.panel,'Complete sidebar'),...side];
  for(const n of full){if(n.name.startsWith('Nav / ')){const v=n.name.slice(6);n.children[0].fill=v===({sections:'Sections',memory:'Memory',artifacts:'Artifacts'}[key])?C.selected:C.panel;}await adds(root,n);}
  if(key==='memory'){
    await adds(root,button('Action / Memory options',1234,194,189,'Map options…'));
    await adds(root,button('Action / Memory hex',1147,676,132,'Hex editor…'));
    await adds(root,button('Action / Memory write',1290,676,133,'Write bytes…'));
    await adds(root,R(1138,68,302,27,C.panel,'Sample label background'));
    await adds(root,T(1148,74,284,'Attached session / illustrative data',11,C.muted));
  }
  if(key==='artifacts')await adds(root,button('Action / Validate output',1226,710,190,'Validate image…'));
}
// Rebuild options reflect the implemented command rather than hiding entry settings.
const rb=roots.rebuild;
const erase=rb.children.filter(n=>n.y>=331).map(n=>n.id);await call('delete_nodes',{ids:erase});
await call('update_nodes',{patches:{[rb.id]:{h:732}}});
await adds(rb,T(20,339,640,'Import recovery',12,C.ink,600));
await adds(rb,T(20,365,640,'Live process: PID 46104 · x86 · required for import recovery',12,C.muted));
function checkbox(name,y,label,on){const mark=icon('check',0,1,C.accent,14);mark.name='Checkmark / '+name;return G('Toggle / '+name,20,y,640,24,[R(0,3,14,14,C.white,'Checkbox',C.border,1),mark,T(24,1,604,label,12,C.ink)]);}
await adds(rb,checkbox('Rebuild cast',405,'Reverse-resolve additional import slots (IAT cast)',false));
await adds(rb,checkbox('Rebuild clean',439,'Restore writable data from the original file',false));
await adds(rb,T(20,486,640,'Advanced image settings (optional)',12,C.ink,600));
await adds(rb,T(20,520,309,'Image base override',11,C.muted,600));await adds(rb,T(347,520,313,'Entry RVA override',11,C.muted,600));
await adds(rb,field('Input / Rebuild base',20,543,310,'Auto / captured base',true));await adds(rb,field('Input / Rebuild entry',347,543,313,'Auto / original entry',true));
await adds(rb,R(20,602,640,43,C.panel,'Rebuild result note',C.border,2));await adds(rb,T(31,613,618,'File production and successful execution are recorded as separate results.',11,C.muted));
await adds(rb,L(20,667,640,0,C.rule));await adds(rb,button('Dialog / Cancel rebuild',453,683,91,'Cancel'));await adds(rb,button('Dialog / Confirm rebuild',555,683,105,'Rebuild',null,true,true));
for(let i=0;i<screens.length;i++){
  const {key,...spec}=screens[i];spec.x=80+(i%4)*1520;spec.y=2230+Math.floor(i/4)*1010;
  const created=await call('create_node',spec);roots[key]={...spec,id:created.id};console.log('Workspace '+key);
}
for(let i=0;i<dialogs.length;i++){
  const {key,...spec}=dialogs[i];spec.x=6320+(i%4)*820;spec.y=80+Math.floor(i/4)*800;
  const created=await call('create_node',spec);roots[key]={...spec,id:created.id};console.log('Dialog '+key);
}
let doc=await call('get_document');for(const key of Object.keys(roots))roots[key]=doc.activePage.nodes.find(n=>n.id===roots[key].id);
// Reusable document styles and neutral surface tokens.
await call('variable_command',{command:{kind:'createCollection',id:'vmpx-desktop-tokens',name:'VMPX / Desktop'}});
for(const [name,value] of Object.entries(C))await call('variable_command',{command:{kind:'createVariable',variable:{id:'vmpx-color-'+name,name:'Surface/'+name,type:'color',value,collectionId:'vmpx-desktop-tokens',description:'Desktop neutral palette'}}});
const presets=[['Body','Segoe UI',12,400],['Caption','Segoe UI',11,400],['Label','Segoe UI',12,600],['Heading','Segoe UI',17,600],['Mono','Consolas',12,400]];
for(const [name,family,fontSize,fontWeight] of presets){const ids=[];for(const root of Object.values(roots))walk(root,n=>{if(n.type==='text'&&n.fontFamily===family&&n.fontSize===fontSize&&n.fontWeight===fontWeight)ids.push(n.id);});await call('text_style_command',{command:{kind:'create',style:{id:'vmpx-style-'+name.toLowerCase(),name:'VMPX / '+name,fontFamily:family,fontSize,fontWeight,lineHeight:1.25},pageId:doc.activePage.id,ids}});}
const interactions=[];
async function bind(node,to,action='navigateTo',extra={}){
  if(!node)throw Error('Missing interaction source '+to);
  const args={sourceNodeId:node.id,action,...(to?{targetFrameId:roots[to].id}:{}),transition:{type:'instant',durationMs:0},...extra};
  const r=await call('add_interaction',args);interactions.push({source:node.id,name:node.name,to,action,id:r.interaction?.id});
}
// Replace old links in the five existing frames with complete prototype routes.
for(const root of Object.values(roots)){
  const stale=[];walk(root,n=>{for(const it of n.interactions||[])stale.push({sourceNodeId:n.id,interactionId:it.id});});
  for(const args of stale)await call('delete_interaction',args);
}
const navKeys={'Overview':'overview','Sections':'sections','Imports':'imports','Modules':'modules','Memory':'memory','Hex editor':'hex','Windows':'windows','Agent':'agent','Watch':'watch','Analysis':'analysis','Artifacts':'artifacts','Session log':'log'};
const actionMap={'Action / Open':['open','openOverlay'],'Action / Attach':['attach','openOverlay'],'Action / Dump':['dump','openOverlay'],'Action / Rebuild':['rebuild','openOverlay'],'Action / Watch':['watch-options','openOverlay'],'Action / Stop':['watch-stopped','navigateTo'],'Action / Save snapshot':['snapshot','openOverlay'],'Action / Capture image':['dump','openOverlay'],'Action / Memory options':['memory-options','openOverlay'],'Action / Memory hex':['hex','navigateTo'],'Action / Memory write':['write','openOverlay'],'Action / Validate output':['run','openOverlay'],'Action / Open output folder':['browse','openOverlay'],'Action / View run log':['log','navigateTo']};
let toggleCount=0;
for(const [key,root] of Object.entries(roots)){
  const nodes=[];walk(root,n=>nodes.push(n));
  for(const n of nodes){
    const route=routes.find(r=>r.name===n.name);
    if(n.name.startsWith('Nav / '))await bind(n,navKeys[n.name.slice(6)]);
    else if(route)await bind(n,route.to,route.action);
    else if(actionMap[n.name]){
      const [to,action]=actionMap[n.name];
      // Disabled native actions have no prototype hit target.
      let disabled=false;walk(n,c=>{if(c.type==='text'&&c.fill===C.disabled)disabled=true;});if(!disabled)await bind(n,to,action);
    }
    else if(n.type==='text'&&['File','Edit','View','Capture','Tools','Help'].includes(n.text)&&n.y===37)await bind(n,n.text.toLowerCase()+'-menu','openOverlay');
    else if(n.type==='frame'&&n.name.startsWith('Filter'))await bind(n,'filter','openOverlay');
    else if(n.type==='text'&&['Sections','Imports','Memory','Artifacts'].includes(n.text)&&n.y===159)await bind(n,navKeys[n.text]);
    else if(n.name==='Dialog / Confirm attach')await bind(n,'memory');
    else if(n.name==='Dialog / Confirm rebuild')await bind(n,'artifacts');
    else if(n.name.startsWith('Dialog / Cancel'))await bind(n,null,'closeOverlay');
    else if(n.name.startsWith('Browse /'))await bind(n,'browse','openOverlay');
    else if(n.name==='Icon / close'&&root.w<1000)await bind(n,null,'closeOverlay');
    if(n.name.startsWith('Toggle / ')){
      const variableId='vmpx-control-'+(++toggleCount),name=n.name.slice(9);
      const sourceSpec=[...screens,...dialogs].find(s=>s.key===key);
      let initial=false;if(sourceSpec)walk(sourceSpec,c=>{if(c.name===n.name)initial=c.initialChecked??false;});
      const mark=byName(n,'Checkmark / '+name);
      await call('variable_command',{command:{kind:'createVariable',variable:{id:variableId,name:'Controls/'+name,type:'boolean',value:initial?'true':'false',collectionId:'vmpx-desktop-tokens'}}});
      if(mark)await call('variable_command',{command:{kind:'bind',pageId:doc.activePage.id,ids:[mark.id],property:'visible',variableId}});
      await bind(n,null,'setVariable',{variableId,variableOperation:'toggle'});
    }
  }
}
// Attach selection includes an incompatible-architecture error path.
const attach=roots.attach;let rowY;walk(attach,n=>{if(n.type==='text'&&n.text==='explorer.exe')rowY=n.y;});
const hit=await adds(attach,G('Attach / Incompatible row',20,rowY-4,600,31,[R(0,0,600,31,null,'Row hit target')]));await bind({...hit,name:'Attach / Incompatible row'},'attach-incompatible','openOverlay');
await call('set_flow_start',{frameId:roots.overview.id,on:true,name:'VMPX / Complete desktop'});
await call('set_flow_start',{frameId:roots.empty.id,on:true,name:'VMPX / Start empty'});
await call('set_flow_start',{frameId:roots.sections.id,on:true,name:'VMPX / File inspection'});
doc=await call('get_document');
// Export IDs, command coverage and full native scene; no backend operations run.
const commands={info:['overview','sections'],imports:['imports','import-options'],launch:['launch'],modules:['modules'],inject:['inject','agent'],dump:['dump','busy','capture-result'],liveimports:['liveimports','import-options'],agentstatus:['agent'],peek:['hex','hex-read'],poke:['write','write-result'],rebuild:['rebuild','artifacts'],windows:['windows'],memmap:['memory','memory-options'],oep:['oep'],snap:['snapshot'],run:['run','artifacts'],deobf:['analysis','analysis-options','analysis-result'],watch:['watch-options','watch','watch-stopped']};
const native={id:doc.docId,name:'VMPX — Complete desktop design',createdAt:new Date().toISOString(),updatedAt:new Date().toISOString(),pages:[{id:doc.activePage.id,name:'Desktop workbench',background:'#F5F5F5',nodes:doc.activePage.nodes,comments:doc.activePage.comments,variableModes:doc.activePage.variableModes}],variables:doc.variables,variableCollections:doc.variableCollections,textStyles:doc.textStyles};
await fs.writeFile(OUT+'/vmpx-desktop.canvasdesk.json',JSON.stringify(native,null,2));
const manifest={docId:doc.docId,pageId:doc.activePage.id,frames:Object.entries(roots).map(([key,n])=>({key,id:n.id,name:n.name,w:n.w,h:n.h,file:key})),commands,interactions,colors:C,toggleCount,limitations:['Design prototype only; process backend is not wired.','Live values and successful completion states are design samples.','Recorded restore/runtime failure remains in reconstruction result.']};
await fs.writeFile(OUT+'/complete-design-manifest.json',JSON.stringify(manifest,null,2));
for(const [key,root] of Object.entries(roots)){const {svg}=await call('export_svg',{ids:[root.id]});await fs.writeFile(OUT+'/'+key+'.svg',svg);}
await call('set_selection',{ids:[roots.overview.id]});await call('zoom_to_fit',{ids:[roots.overview.id]});
console.log(JSON.stringify({frames:Object.keys(roots).length,interactions:interactions.length,toggles:toggleCount,commands:Object.keys(commands).length}));
