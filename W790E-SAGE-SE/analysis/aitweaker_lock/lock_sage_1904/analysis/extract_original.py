"""Read official SAGE SE 1904 artifacts and compare with ACE evidence; no device access."""
from pathlib import Path
import collections, hashlib, json, lzma, struct, sys, uuid, zlib
HERE = Path(__file__).resolve().parent
BASE = HERE.parents[1]
ROOT = BASE.parents[1]
sys.path[:0] = [str(ROOT/'tools/pydeps'), str(BASE)]
import pefile
from inspect_setup import string_packages
from inspect_forms import packages, decode, QUESTIONS
PUB = BASE/'official_W790E_SAGE_SE_1904'
CAP = PUB/'W790E_SAGE_SE_1904/Pro-WS-W790E-SAGE-SE-ASUS-1904.CAP'
DUMP = Path(str(CAP)+'.dump')
MODULES = HERE/'modules'
ACE = BASE/'hardware_20261102_W790_ACE_E9B906DF'

def sha(b): return hashlib.sha256(b).hexdigest()
def save(path, data): path.write_text(json.dumps(data,ensure_ascii=False,indent=2)+'\n',encoding='utf8')

def main():
    MODULES.mkdir(parents=True,exist_ok=True)
    identities = {'Setup':'899407D7-99FE-43D8-9A21-79EC328CAC21','AMITSE':'B1DA0ADF-4F77-4070-A88E-BFFE1C60529A','PasswordSupport':'AF1450C2-70DE-44D5-80B1-B90D44277990'}
    meta={}
    for name,guid in identities.items():
        files=[p.parent for p in DUMP.rglob('info.txt') if ('File GUID: '+guid) in p.read_text()]
        assert len(files)==1,(name,files)
        pes=list(files[0].rglob('*PE32 image section/body.bin'))
        assert len(pes)==1,(name,pes)
        data=pes[0].read_bytes(); pe=pefile.PE(data=data)
        target=MODULES/f'{name}.efi'; target.write_bytes(data)
        sec=next(s for s in pe.sections if s.Name.rstrip(b'\0')==b'.text')
        text=sec.get_data()[:sec.Misc_VirtualSize]
        ace=(ACE/f'modules/{name}.efi').read_bytes(); ape=pefile.PE(data=ace)
        asec=next(s for s in ape.sections if s.Name.rstrip(b'\0')==b'.text')
        meta[name]={'guid':guid,'path':str(target),'sha256':sha(data),'source_path':str(pes[0]),'text_rva':hex(sec.VirtualAddress),'text_size':hex(sec.Misc_VirtualSize),'text_crc32':f'{zlib.crc32(text):08X}','entry':hex(pe.OPTIONAL_HEADER.AddressOfEntryPoint),'image_size':pe.OPTIONAL_HEADER.SizeOfImage,'exception_functions':0,'ace_sha256':sha(ace),'identical_to_ace':data==ace,'text_identical_to_ace':text==asec.get_data()[:asec.Misc_VirtualSize]}
        strings=string_packages(data); save(MODULES/f'{name}_strings.json',strings)
        if name=='Setup':
            assert len(strings)==1
            packs=[decode(data,p,strings[0]['strings']) for p in packages(data)]
            save(MODULES/'Setup_IFR.json',packs)
    save(HERE/'module_metadata.json',meta)
    recs=[r for p in packs for r in p['records']]
    forms={r['form_id']:r for r in recs if r['op']==1}
    roots=[r for r in forms.values() if r.get('title')=='Ai Tweaker']; assert len(roots)==1
    refs=[r for r in recs if r['op']==15 and 'target_form' in r and not r.get('target_formset')]
    reached=set(); todo=[roots[0]['form_id']]
    while todo:
        f=todo.pop()
        if f in reached: continue
        reached.add(f)
        todo.extend(r['target_form'] for r in refs if r.get('form')==f and r['target_form'] in forms)
    questions=[r for r in recs if r['op'] in QUESTIONS and r.get('form') in reached]
    brief={'root':roots[0],'formset_guid':next(r['guid'] for r in recs if r['op']==14),'total_static_forms':len(forms),'reachable_forms_by_local_ifr_ref':[{k:forms[f][k] for k in ('form_id','title','offset')} for f in sorted(reached)],'reachable_questions_count':len(questions),'question_varstores':dict(collections.Counter(r['varstore_id'] for r in questions)),'password_questions_in_all_setup_forms':[r for r in recs if r['op']==8],'password_questions_reachable_from_ai_tweaker':[r for r in questions if r['op']==8],'incoming_local_refs':[r for r in refs if r['target_form'] in reached and r.get('form') not in reached],'scope':'Static local IFR REF reachability only; vendor top tabs, Favorites/search/profile flows are not proven by this graph.'}
    save(HERE/'forms_1904.json',brief)
    stores=[r for r in recs if r['op'] in (36,37,38)]
    save(HERE/'varstores.json',stores)
    acerecs=[r for p in json.loads((ACE/'modules/Setup_IFR.json').read_text(encoding='utf8')) for r in p['records']]
    def semantic(r):return {k:v for k,v in r.items() if k not in ('offset','parents','end')}
    comparison={'setup_records':len(recs),'ace_records':len(acerecs),'semantically_identical_records':len(recs)==len(acerecs) and [semantic(r) for r in recs]==[semantic(r) for r in acerecs],'form_id_title_list_equal':[(r['form_id'],r['title']) for r in recs if r['op']==1]==[(r['form_id'],r['title']) for r in acerecs if r['op']==1],'sage_questions':len(questions),'ace_questions':json.loads((ACE/'forms_1904.json').read_text(encoding='utf8'))['reachable_questions_count'],'sage_varstores':stores,'ace_varstores':[r for r in acerecs if r['op'] in (36,37,38)]}
    save(HERE/'ifr_comparison.json',comparison)
    image=CAP.read_bytes(); outer=0x3181000; container=outer+0x78; section=container+24
    n=int.from_bytes(image[container+20:container+23],'little'); sn=int.from_bytes(image[section:section+3],'little')
    raw=lzma.decompress(image[section+24:section+sn],format=lzma.FORMAT_ALONE)
    source={'board':'ASUS Pro WS W790E-SAGE SE','version':'1904','support_url':'https://www.asus.com/motherboards-components/motherboards/workstation/pro-ws-w790e-sage-se/helpdesk_bios?model2Name=Pro-WS-W790E-SAGE-SE','download_url':'https://dlcdnets.asus.com/pub/ASUS/mb/BIOS/Pro-WS-W790E-SAGE-SE-ASUS-1904.zip','publisher_zip_sha256':'1d01a9a3eff7a264e4009281466e669a0631cedf6095e101ced520f86fb9c480','zip_sha256':sha((PUB/'Pro-WS-W790E-SAGE-SE-ASUS-1904.zip').read_bytes()),'cap_sha256':sha(image),'cap_size':len(image),'outer_fv':hex(outer),'outer_fv_size':hex(struct.unpack_from('<Q',image,outer+32)[0]),'container':hex(container),'container_guid':str(uuid.UUID(bytes_le=image[container:container+16])),'original_container_ffs_size':n,'aligned_container_allocation':(n+7)&~7,'nested_section':hex(section),'inner_fv_offset':16,'inner_fv_size':hex(struct.unpack_from('<Q',raw,16+32)[0]),'decompressed_container_size':len(raw),'modules':meta}
    assert source['zip_sha256']==source['publisher_zip_sha256']
    save(HERE/'original_identity.json',source)
    print(json.dumps({'source':{k:v for k,v in source.items() if k!='modules'},'modules':meta,'ifr':{k:v for k,v in comparison.items() if 'varstores' not in k}},indent=2))
if __name__=='__main__':main()
