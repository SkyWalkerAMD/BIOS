from pathlib import Path
import json,sys
H=Path(__file__).resolve().parent
for name in ['W890-configcall3e424']:
    x=json.loads((H/'rea'/f'{name}.json').read_text())['structuredContent']
    text=x['normalized_result']['pseudocode']
    (H/f'{name}.c.txt').write_text(text)
    if 'callback' in name:
        lines=text.splitlines()
        for i,line in enumerate(lines):
            if '+ 0x10)' in line or 'local_70[' in line:
                print('\n'.join(lines[max(0,i-7):i+8]))
    else: print(text)
