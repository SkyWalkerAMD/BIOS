"""Known-size LZMA1EXT wire format with bounded explicit search depth."""
import ctypes as c,struct,lzma,sys
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parent.parent/'release_review'))
from lzma_known_size import Options,Filter,FILTER_EXT,library

def encode(data,dictionary,depth):
    if dictionary not in (0x1000000,0x2000000)or depth not in (512,2048,8192)or len(data)>0x2200000:
        raise ValueError('bounded compression profile')
    lib=library();opts=Options()
    if lib.lzma_lzma_preset(c.byref(opts),9):raise ValueError('preset')
    opts.dict_size=dictionary;opts.lc,opts.lp,opts.pb=3,0,2
    opts.mode,opts.nice_len,opts.mf,opts.depth=2,273,0x14,depth
    opts.ext_flags=0;opts.ext_size_low,opts.ext_size_high=len(data)&0xffffffff,len(data)>>32
    filters=(Filter*2)(Filter(FILTER_EXT,c.addressof(opts)),Filter(0xffffffffffffffff,None))
    memory=lib.lzma_raw_encoder_memusage(filters)
    if memory>512*1024*1024:raise ValueError('encoder memory bound')
    props=c.create_string_buffer(5)
    if lib.lzma_properties_encode(c.byref(filters[0]),props):raise ValueError('properties')
    inp=c.create_string_buffer(data);capacity=len(data)*2+65536;out=c.create_string_buffer(capacity);pos=c.c_size_t(0)
    result=lib.lzma_raw_buffer_encode(filters,None,inp,len(data),out,c.byref(pos),capacity)
    if result:raise ValueError('raw encode '+str(result))
    packed=props.raw+struct.pack('<Q',len(data))+out.raw[:pos.value]
    if lzma.decompress(packed,format=lzma.FORMAT_ALONE)!=data:raise ValueError('roundtrip')
    return packed
