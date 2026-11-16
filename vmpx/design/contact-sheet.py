from pathlib import Path
from PIL import Image, ImageDraw, ImageFont
import json

root = Path('D:/cracker/vmpx/design')
manifest = json.loads((root / 'complete-design-manifest.json').read_text())
keys = ['overview', 'sections', 'imports', 'liveimports', 'modules', 'memory',
        'hex', 'windows', 'agent', 'watch', 'analysis', 'artifacts',
        'log', 'state-attach', 'state-rebuild', 'state-watch-options']
tile_w, tile_h = 480, 330
sheet = Image.new('RGB', (tile_w * 4, tile_h * 4 + 78), '#f0f1f3')
draw = ImageDraw.Draw(sheet)
font = ImageFont.truetype('C:/Windows/Fonts/segoeui.ttf', 16)
title = ImageFont.truetype('C:/Windows/Fonts/segoeuib.ttf', 23)
draw.text((22, 16), 'VMPX / Complete desktop workbench', font=title, fill='#20262d')
draw.text((22, 48), 'Built by Olivia — https://discord.gg/ojailbreaks', font=font, fill='#67717d')
for i, key in enumerate(keys):
    x, y = (i % 4) * tile_w + 14, (i // 4) * tile_h + 88
    frame = next(frame for frame in manifest['frames'] if frame['key'] == key)
    draw.text((x, y), frame['name'], font=font, fill='#20262d')
    image = Image.open(root / (frame['file'] + '.png')).convert('RGB')
    image.thumbnail((tile_w - 28, tile_h - 46), Image.Resampling.LANCZOS)
    sheet.paste(image, (x, y + 29))
sheet.save(root / 'complete-desktop-overview.png')
print(root / 'complete-desktop-overview.png')
