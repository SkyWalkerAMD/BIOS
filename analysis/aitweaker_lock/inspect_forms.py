"""Read UEFI IFR packages and map Ai Tweaker forms; never modifies firmware."""
import collections
import json
import re
import struct
import uuid
from inspect_setup import OUT, TAGS, get_module, string_packages

NAMES = {1:'FORM',2:'SUBTITLE',3:'TEXT',4:'IMAGE',5:'ONE_OF',6:'CHECKBOX',7:'NUMERIC',
         8:'PASSWORD',9:'ONE_OF_OPTION',10:'SUPPRESS_IF',12:'ACTION',13:'RESET_BUTTON',
         14:'FORM_SET',15:'REF',16:'NO_SUBMIT_IF',17:'INCONSISTENT_IF',18:'EQ_ID_VAL',
         19:'EQ_ID_ID',20:'EQ_ID_VAL_LIST',21:'AND',22:'OR',23:'NOT',24:'RULE',25:'GRAY_OUT_IF',
         26:'DATE',27:'TIME',28:'STRING',29:'REFRESH',30:'DISABLE_IF',31:'ANIMATION',
         32:'TO_LOWER',33:'TO_UPPER',34:'MAP',35:'ORDERED_LIST',36:'VARSTORE',37:'VARSTORE_NAME_VALUE',
         38:'VARSTORE_EFI',39:'VARSTORE_DEVICE',40:'VERSION',41:'END',42:'MATCH',43:'GET',44:'SET',
         45:'READ',46:'WRITE',47:'EQUAL',48:'NOT_EQUAL',49:'GREATER_THAN',50:'GREATER_EQUAL',
         51:'LESS_THAN',52:'LESS_EQUAL',53:'BITWISE_AND',54:'BITWISE_OR',55:'BITWISE_NOT',
         56:'SHIFT_LEFT',57:'SHIFT_RIGHT',58:'ADD',59:'SUBTRACT',60:'MULTIPLY',61:'DIVIDE',
         62:'MODULO',63:'RULE_REF',64:'QUESTION_REF1',65:'QUESTION_REF2',66:'UINT8',67:'UINT16',
         68:'UINT32',69:'UINT64',70:'TRUE',71:'FALSE',72:'TO_UINT',73:'TO_STRING',74:'TO_BOOLEAN',
         75:'MID',76:'FIND',77:'TOKEN',78:'STRING_REF1',79:'STRING_REF2',80:'CONDITIONAL',
         81:'QUESTION_REF3',82:'ZERO',83:'ONE',84:'ONES',85:'UNDEFINED',86:'LENGTH',87:'DUP',
         88:'THIS',89:'SPAN',90:'VALUE',91:'DEFAULT',92:'DEFAULTSTORE',93:'FORM_MAP',94:'CATENATE',
         95:'GUID',96:'SECURITY',97:'MODAL_TAG',98:'REFRESH_ID',99:'WARNING_IF',100:'MATCH2'}
QUESTIONS = {5,6,7,8,12,15,26,27,28,35}


def packages(data):
    found = []
    for match in re.finditer(b'\x0e[\xa7\x97]', data):
        start = match.start()-4
        header = struct.unpack_from('<I', data, start)[0]
        length = header & 0xffffff
        if header >> 24 != 2 or length < 27 or start+length > len(data):
            continue
        records, stack, pos = [], [], start+4
        while pos < start+length:
            op, rawlen = data[pos:pos+2]
            size, scope = rawlen & 127, bool(rawlen & 128)
            assert op in NAMES and size >= 2 and pos+size <= start+length, (hex(pos),op,size)
            rec = {'offset':pos,'op':op,'type':NAMES[op],'scope':scope,'size':size,
                   'parents':stack.copy(),'hex':data[pos:pos+size].hex()}
            records.append(rec)
            if op == 41:
                assert stack, hex(pos)
                parent = stack.pop()
                records[parent]['end'] = pos+size
            elif scope:
                stack.append(len(records)-1)
            pos += size
        assert not stack and pos == start+length
        found.append({'offset':start,'length':length,'records':records})
    return found


def decode(data, pack, strings):
    records = pack['records']
    u16 = lambda p:struct.unpack_from('<H',data,p)[0]
    for i, rec in enumerate(records):
        p, op, size = rec['offset'], rec['op'], rec['size']
        rec['form'] = next((records[k]['form_id'] for k in reversed(rec['parents']) if records[k]['op']==1), None)
        if op == 1:
            rec['form_id'], rec['title_id'] = u16(p+2), u16(p+4)
            rec['title'] = strings.get(rec['title_id'])
        elif op == 14:
            rec['guid'] = str(uuid.UUID(bytes_le=data[p+2:p+18]))
            rec['title_id'] = u16(p+18)
            rec['title'] = strings.get(rec['title_id'])
        elif op == 36:
            rec['guid'] = str(uuid.UUID(bytes_le=data[p+2:p+18]))
            rec['varstore_id'], rec['varstore_size'] = u16(p+18), u16(p+20)
            rec['name'] = data[p+22:p+size].rstrip(b'\0').decode('ascii')
        elif op == 38 and size >= 27:
            rec['varstore_id'] = u16(p+2)
            rec['guid'] = str(uuid.UUID(bytes_le=data[p+4:p+20]))
            rec['attributes'] = struct.unpack_from('<I',data,p+20)[0]
            rec['varstore_size'] = u16(p+24)
            rec['name'] = data[p+26:p+size].rstrip(b'\0').decode('ascii')
        elif op in QUESTIONS:
            rec['prompt_id'], rec['help_id'], rec['question_id'], rec['varstore_id'], rec['var_offset'] = struct.unpack_from('<HHHHH',data,p+2)
            rec['flags'] = data[p+12]
            rec['prompt'],rec['help'] = strings.get(rec['prompt_id']),strings.get(rec['help_id'])
            if op == 15 and size >= 15:
                rec['target_form'] = u16(p+13)
                if size >= 17:
                    rec['target_question'] = u16(p+15)
                if size >= 33:
                    rec['target_formset'] = str(uuid.UUID(bytes_le=data[p+17:p+33]))
            if op == 8:
                rec['min_size'],rec['max_size']=u16(p+13),u16(p+15)
        elif op in (2,3,13):
            rec['prompt_id'] = u16(p+2)
            rec['prompt'] = strings.get(rec['prompt_id'])
        elif op == 95:
            rec['guid'] = str(uuid.UUID(bytes_le=data[p+2:p+18]))
    return pack


def main():
    summary = {}
    for tag in TAGS:
        m,s,data = get_module(tag,'Setup')
        strings = string_packages(data)[0]['strings']
        packs = [decode(data,p,strings) for p in packages(data)]
        folder = OUT/tag
        (folder/'Setup_IFR.json').write_text(json.dumps(packs,ensure_ascii=False,indent=2),encoding='utf8')
        lines = []
        for pack in packs:
            for r in pack['records']:
                fields = {k:v for k,v in r.items() if k not in ('offset','op','type','scope','size','parents','hex','help')}
                lines.append(f"{r['offset']:08x} {'  '*len(r['parents'])}{r['type']} {json.dumps(fields,ensure_ascii=False)} [{r['hex']}]")
        (folder/'Setup_IFR.txt').write_text('\n'.join(lines),encoding='utf8')
        recs = [r for p in packs for r in p['records']]
        roots = [r for r in recs if r['op']==1 and r['title']=='Ai Tweaker']
        assert len(roots)==1
        root = roots[0]
        forms = {r['form_id']:r for r in recs if r['op']==1}
        refs = [r for r in recs if r['op']==15 and 'target_form' in r and not r.get('target_formset')]
        todo, reached = [root['form_id']], set()
        while todo:
            form=todo.pop()
            if form in reached:
                continue
            reached.add(form)
            todo.extend(r['target_form'] for r in refs if r['form']==form and r['target_form'] in forms)
        questions = [r for r in recs if r['op'] in QUESTIONS and r['form'] in reached]
        interesting = [r for r in recs if re.search(r'password|Ai.?Tweaker|overclock|XMP|favorite|profile',str(r.get('prompt') or r.get('title') or ''),re.I)]
        brief = {k:root[k] for k in ('offset','end','form_id','title_id','title')}
        brief['formset'] = next(r['guid'] for r in recs if r['op']==14)
        brief['subforms']=[{'id':fid,'title':forms[fid]['title'],'offset':forms[fid]['offset']} for fid in sorted(reached)]
        brief['questions_count']=len(questions)
        brief['varstore_ids']=dict(collections.Counter(r['varstore_id'] for r in questions))
        brief['varstores']=[r for r in recs if r['op'] in (36,38) and r['varstore_id'] in brief['varstore_ids']]
        brief['password_questions']=[r for r in recs if r['op']==8]
        brief['incoming_refs']=[r for r in refs if r['target_form'] in reached and r['form'] not in reached]
        brief['interesting']=interesting
        summary[tag]=brief
        print(tag,'AiTweaker',hex(root['form_id']),'fileoffset',hex(root['offset']),'forms',len(reached),'questions',len(questions))
        print('subforms',[(hex(fid),forms[fid]['title']) for fid in sorted(reached)])
        print('password questions',[(r['prompt'],hex(r['question_id']),hex(r['offset']),hex(r['varstore_id']),hex(r['flags'])) for r in brief['password_questions']])
    (OUT/'form_findings.json').write_text(json.dumps(summary,ensure_ascii=False,indent=2),encoding='utf8')


if __name__=='__main__':
    main()
