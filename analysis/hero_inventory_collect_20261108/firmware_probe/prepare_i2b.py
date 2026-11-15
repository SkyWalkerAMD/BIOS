"""Create the separate I2B source tree once; keep I2 source/media/evidence fixed."""
from pathlib import Path
import hashlib,json
P=Path(__file__).resolve().parent;OLD=P/'i2-build';OUT=P/'i2b-build'
def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()
def main():
 if (OUT/'source/firmware_probe.c').exists():raise FileExistsError('I2B source exists; edit that source directly, do not overwrite it')
 (OUT/'source').mkdir(parents=True,exist_ok=True);rows=[]
 for src in (OLD/'source').rglob('*'):
  if not src.is_file():continue
  dest=OUT/'source'/src.relative_to(OLD/'source');dest.parent.mkdir(parents=True,exist_ok=True)
  data=src.read_text().replace('HERO-FW-ID-I2','HERO-FW-ID-I2B').replace('HERO FW ID I2','HERO FW ID I2B')
  dest.write_text(data,encoding='ascii',newline='\n');rows.append({'source':str(src),'source_sha256':sha(src),'target':str(dest.relative_to(OUT))})
 for name in ['build.py','decode_captures.py']:
  data=(OLD/name).read_text().replace('HERO-FW-ID-I2','HERO-FW-ID-I2B').replace('HERO_FW_ID_I2','HERO_FW_ID_I2B').replace('FW ID I2','FW ID I2B')
  if name=='build.py':
   data=data.replace("'firmware_probe'","'firmware_probe','fw_sections'")
   data=data.replace("'/export:firmware_probe'","'/export:fp_sections_parse','/export:firmware_probe'")
  (OUT/name).write_text(data,encoding='ascii',newline='\n')
 (OUT/'source-provenance.json').write_text(json.dumps(rows,indent=2)+'\n')
 print('Created isolated I2B source tree.')
if __name__=='__main__':main()
