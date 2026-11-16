const { app, BrowserWindow } = require('electron');
const fs = require('node:fs/promises');
const path = require('node:path');

app.disableHardwareAcceleration();
app.on('window-all-closed', () => {});
const root = 'D:/cracker/vmpx/design';
const inputs = require('./complete-design-manifest.json').frames.map(frame => frame.file);

app.whenReady().then(async () => {
  const checks = [];
  for (const name of inputs) {
    const svg = await fs.readFile(path.join(root, name + '.svg'), 'utf8');
    const width = Number(svg.match(/<svg[^>]* width="(\d+)"/)[1]);
    const height = Number(svg.match(/<svg[^>]* height="(\d+)"/)[1]);
    const win = new BrowserWindow({ width, height, useContentSize:true, frame:false,
      show:false, backgroundColor:'#ffffff', webPreferences:{offscreen:true, sandbox:true, contextIsolation:true} });
    await win.loadURL('data:text/html;charset=utf-8,' + encodeURIComponent(
      '<!doctype html><html><head><meta charset="utf-8"><style>html,body{margin:0;padding:0;background:white;overflow:hidden}svg{display:block}</style></head><body>' + svg + '</body></html>'
    ));
    win.webContents.debugger.attach('1.3');
    await win.webContents.debugger.sendCommand('Emulation.setDeviceMetricsOverride', {
      width, height, deviceScaleFactor:1, mobile:false,
      screenWidth:width, screenHeight:height,
    });
    await win.webContents.executeJavaScript('document.fonts.ready.then(() => true)');
    await new Promise(resolve => setTimeout(resolve, 300));
    const metrics = await win.webContents.executeJavaScript(`(() => {
      const overflow = [], collisions = [];
      const measured = [];
      for (const node of document.querySelectorAll('text')) {
        if (getComputedStyle(node).display === 'none' || getComputedStyle(node).visibility === 'hidden') continue;
        const rect = node.getBoundingClientRect();
        if (rect.left < -1 || rect.top < -1 || rect.right > innerWidth + 1 || rect.bottom > innerHeight + 1)
          overflow.push({text:node.textContent,box:{x:rect.x,y:rect.y,w:rect.width,h:rect.height}});
        measured.push({node,rect,text:node.textContent});
      }
      for(let i=0;i<measured.length;i++)for(let j=i+1;j<measured.length;j++){
        const a=measured[i],b=measured[j];
        if(a.node.parentElement!==b.node.parentElement)continue;
        const dx=Math.min(a.rect.right,b.rect.right)-Math.max(a.rect.left,b.rect.left);
        const dy=Math.min(a.rect.bottom,b.rect.bottom)-Math.max(a.rect.top,b.rect.top);
        if(dx>2&&dy>2)collisions.push({a:a.text,b:b.text,dx,dy});
      }
      return {width:innerWidth,height:innerHeight,texts:document.querySelectorAll('text').length,overflow,collisions};
    })()`);
    const capture = await win.webContents.debugger.sendCommand('Page.captureScreenshot', {
      format:'png',captureBeyondViewport:true,
      clip:{x:0,y:0,width,height,scale:1},
    });
    await fs.writeFile(path.join(root,name+'.png'),Buffer.from(capture.data,'base64'));
    checks.push({name,...metrics});
    console.log(JSON.stringify({name,width,height,texts:metrics.texts,overflow:metrics.overflow.length,collisions:metrics.collisions.length}));
    win.destroy();
  }
  await fs.writeFile(path.join(root,'visual-checks.json'),JSON.stringify(checks,null,2));
  app.exit(0);
}).catch(error=>{console.error(error);app.exit(1);});
