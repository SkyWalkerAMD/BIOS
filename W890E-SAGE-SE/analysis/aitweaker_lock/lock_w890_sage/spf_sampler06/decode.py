"""Interpret only the exact 70-byte diagnostic format; never dereference addresses."""
import struct

FIELDS=('source','source_pages','source_guids','current_blob','current_pages',
        'declared_size','source_page_count','first_page_offset','source_page0_hii',
        'header_parent_field','header_guid_index','header_form_id')
FORMAT='<5Q3IQ3HI'
VALID=0xfff;CODE=1<<12;HEADER=1<<13;POINTERS=1<<14;COUNTS=1<<15;COMPLETE=1<<16
ZERO=1<<17;NONZERO=1<<18;UNSTABLE=1<<19;PROFILE=1<<20;UNREADABLE=1<<21;INVALID=1<<22;PROBE=1<<23

def decode_snapshot(raw):
    if len(raw)!=70:
        raise ValueError('SPF snapshot must be exactly 70 bytes')
    values=struct.unpack(FORMAT,raw);mask=values[-1]
    if mask & ~0xffffff:
        raise ValueError('Reserved status bits')
    result={}
    for i,key in enumerate(FIELDS):
        valid=bool(mask & (1<<i))
        if not valid and values[i]!=0:
            raise ValueError('Unavailable field contains nonzero data')
        result[key]=values[i] if valid else None
    if mask&VALID and not mask&CODE:
        raise ValueError('Fields without code-profile observation')
    if mask&COMPLETE and ((mask&VALID)!=VALID or (mask&(CODE|HEADER|POINTERS|COUNTS))!=(CODE|HEADER|POINTERS|COUNTS)):
        raise ValueError('Inconsistent complete-read flag')
    if mask&ZERO and mask&NONZERO:
        raise ValueError('Contradictory candidate flags')
    candidate=result['source_page0_hii']
    if mask&(ZERO|NONZERO):
        if candidate is None or bool(mask&ZERO)!=((candidate&0xffffffff)==0):
            raise ValueError('Candidate flag mismatch')
    if mask&COUNTS and (result['source_page_count']!=379 or result['first_page_offset']!=0x650):
        raise ValueError('Inconsistent fixed-count flag')
    if mask&HEADER and result['declared_size']!=0xf245c:
        raise ValueError('Inconsistent original header declaration')
    if mask&POINTERS and (result['source'] is None or result['source_pages']!=result['source']+0x60 or result['source_guids']!=result['source']+0xf2394):
        raise ValueError('Inconsistent pointer relation')
    derived={}
    if mask&(HEADER|POINTERS|COUNTS)==(HEADER|POINTERS|COUNTS) and candidate is not None:
        derived['one_past_slot_relative']=result['source_pages']-result['source']+4+4*result['source_page_count']
        derived['slot_overlaps_first_page_hii']=derived['one_past_slot_relative']==result['first_page_offset']
        derived['candidate_offset_low32']=candidate&0xffffffff
        if derived['candidate_offset_low32']==0 and result['header_parent_field'] is not None:
            derived['known_header_would_skip_guid_read']=result['header_parent_field']!=0
            if result['header_parent_field']==0 and result['header_guid_index'] is not None:
                target=result['source_guids']-result['source']+0x14*result['header_guid_index']+0x12
                derived['computed_guid_read_relative_only']=target
                derived['computed_guid_read_within_declared_size']=0<=target and target+2<=result['declared_size']
                derived['computed_address_was_dereferenced']=False
    return {'fields':result,'status_mask':mask,'derived':derived,'authorization':False}

def decode_pair(a,b):
    first=decode_snapshot(a);second=decode_snapshot(b)
    def without_unstable(raw):
        return raw[:66]+struct.pack('<I',struct.unpack_from('<I',raw,66)[0]&~UNSTABLE)
    equal=without_unstable(a)==without_unstable(b)
    flagged=bool(first['status_mask']&UNSTABLE) and bool(second['status_mask']&UNSTABLE)
    if (bool(first['status_mask']&UNSTABLE)!=bool(second['status_mask']&UNSTABLE)) or flagged==equal:
        raise ValueError('Pair instability flags disagree with observations')
    return {'a':first,'b':second,'observations_equal':equal,
            'both_reads_complete':bool(first['status_mask']&COMPLETE and second['status_mask']&COMPLETE),
            'authorization':False,
            'limits':['Post-Setup observations do not establish first-parser values.',
                      'Declared/mapped spans do not prove allocator ownership.',
                      'No candidate address is dereferenced by this decoder.']}
