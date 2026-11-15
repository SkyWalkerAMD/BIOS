"""Derive the existing independent raw parser runner for the exact09 package."""
from pathlib import Path
import hashlib,json
HERE=Path(__file__).resolve().parent;D04=HERE.parent
source=D04/'ram_transaction08_independent_review/verify_delivery.py'
text=source.read_text()
replacements={
 'ram_test08_delivery':'ram_test09_delivery','RAM_TEST08':'RAM_TEST09','ram_test08_qr.py':'ram_test09_qr.py',
 'e0793175f78b6488c8222b65f0d5321d97e881bd06dca033a314d3fa8d307486':'3a1def1697c50d1a61b20fc205539fca24107d12891d62b2e971dd6ccde7d1b9',
 '44aa175e37bc367da4ded343df814ca0f3271391bc03cc53fc73371ebfd61dfe':'05dccec80c7ae1c831abc39dd5e0633a0d411584dd020a646cd2642195686d3d',
 '0701fc97ea8397138228a7ee1a605668e61a21e21a9549bd4fb47bd11c3e3e7f':'5ccb06b7ddce9a0685502ee6b6bf706ec610ab3dece358adb090abcdd6f3df8a',
 '20261103_230018':'20261104_001716','==175616':'==187904'}
for a,b in replacements.items():assert a in text,a;text=text.replace(a,b)
out=HERE/'verify_delivery.py';out.write_text(text)
sha=lambda p:hashlib.sha256(p.read_bytes()).hexdigest()
(HERE/'delivery_derivation.json').write_text(json.dumps({'source':str(source),'source_sha256':sha(source),'output_sha256':sha(out),'replacements':replacements,'parser_logic_changed':False},indent=2)+'\n')
