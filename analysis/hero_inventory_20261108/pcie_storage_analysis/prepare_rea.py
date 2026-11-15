"""Create one owned, offline REA leaf analysis from known caller targets."""
from pathlib import Path
import json
OUT=Path(__file__).resolve().parent
ROOT=OUT.parents[2]
session=OUT/'rea-leaves'
(session/'commands').mkdir(parents=True,exist_ok=True)
(session/'seeds.tsv').write_bytes((OUT.parent/'rea-legacy/seeds.tsv').read_bytes())
def command(name,value):
 path=session/'commands'/name
 assert not path.exists()
 path.write_text(json.dumps(value)+'\n')
command('001-open.json',dict(name='open_binary',arguments=dict(provider_id='ghidra',path=str(ROOT/'analysis/hero_remote_bios_r3/reference/AB78D6A5-7E2A-47AA-9F32-780793C0DADB.efi'))))
command('002-pcie-storage.json',dict(name='batch_decompile',arguments=dict(addresses=['0x73e0','0xe6a8','0x5624','0xb4b4','0xb31c','0x9b8c'])) )
