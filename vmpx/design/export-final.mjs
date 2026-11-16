import fs from 'node:fs/promises';
const OUT='D:/cracker/vmpx/design';
const api=async(tool,args={})=>{const r=await fetch('http://127.0.0.1:7843/call',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({tool,args}),signal:AbortSignal.timeout(120000)});const j=await r.json();if(j.error)throw Error(tool+': '+j.error);return j;};
const m=JSON.parse(await fs.readFile(OUT+'/complete-design-manifest.json','utf8'));
const doc=await api('get_document');
for(const f of m.frames){let {svg}=await api('export_svg',{ids:[f.id]});const n=doc.activePage.nodes.find(n=>n.id===f.id);svg=svg.replace(/(<svg\b[^>]*?)width="[^"]*"/,'$1width="'+f.w+'"').replace(/(<svg\b[^>]*?)height="[^"]*"/,'$1height="'+f.h+'"').replace(/viewBox="([\d.-]+) ([\d.-]+) [\d.-]+ [\d.-]+"/,'viewBox="0 0 '+f.w+' '+f.h+'"').replace(/<g transform="translate\([^)]*\)">/,'<g transform="translate('+(-n.x)+','+(-n.y)+')">');await fs.writeFile(OUT+'/'+f.file+'.svg',svg);}
console.log('Exported '+m.frames.length+' exact-size SVG previews.');
