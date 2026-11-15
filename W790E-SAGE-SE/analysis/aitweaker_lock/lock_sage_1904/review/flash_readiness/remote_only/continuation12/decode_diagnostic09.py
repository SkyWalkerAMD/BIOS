"""Decode a transcribed six-line diagnostic09 summary; not a full RAM record.

No OCR guessing, hardware access, unknown-field correction or secret input.
The provider format must be independently bound before physical acceptance.
"""
from pathlib import Path
import hashlib,json,re,struct,sys,zlib

LAYOUT = [
    ('D09', ['R','P','A'], 16),
    ('F', ['H','E','D','K'], 8),
    ('R', ['H','E','D','C'], 8),
    ('P', ['I','F','O','V'], 8),
    ('C', ['K','T','V','H','O'], 8),
    ('S', ['V','F','CRC'], 8),
]


def decode(text):
    if not isinstance(text,str) or len(text)>2048 or not text.isascii():
        raise ValueError('Bounded ASCII transcription required')
    lines=text.strip().splitlines()
    if len(lines)!=6:
        raise ValueError('Exactly six diagnostic lines required')
    fields={}
    binary=bytearray()
    for line,(prefix,labels,width) in zip(lines,LAYOUT):
        expression=re.escape(prefix)+''.join(r'\s+'+re.escape(k)+'=([0-9A-F]{'+str(width)+'})' for k in labels)
        match=re.fullmatch(expression,line.strip())
        if not match:
            raise ValueError('Invalid line '+prefix+'; no automatic OCR substitutions are applied')
        values=[int(v,16) for v in match.groups()]
        fields[prefix]=dict(zip(labels,values))
        for label,value in zip(labels,values):
            if label!='CRC':
                binary.extend(struct.pack('<Q' if width==16 else '<I',value))
    if len(binary)!=100:
        raise ValueError('Display schema byte count mismatch')
    checksum=zlib.crc32(binary)&0xffffffff
    if fields['S']['CRC']!=checksum:
        raise ValueError('Displayed scalar checksum mismatch')
    return {'status':'PASS_DISPLAYED_SCALARS_CRC_ONLY','display_scalar_bytes':100,
            'display_crc32':f'{checksum:08X}','fields_by_printed_label':fields,
            'text_sha256':hashlib.sha256(text.encode('ascii')).hexdigest(),
            'scalar_sha256':hashlib.sha256(binary).hexdigest(),
            'limits':'Verifies only the100 displayed scalar bytes. Not the full256B record, source provenance, current request freshness, policy correctness or firmware acceptance.'}


if __name__=='__main__':
    if len(sys.argv)!=2:
        raise SystemExit('decode_diagnostic09.py TRANSCRIBED_SIX_LINES.txt')
    print(json.dumps(decode(Path(sys.argv[1]).read_text(encoding='ascii')),indent=2))
