"""Create isolated INV02 sources from pinned INV01; never touch INV01 outputs."""
from pathlib import Path
import difflib,hashlib,json,shutil
HERE=Path(__file__).resolve().parent;OLD=HERE.with_name('spi_inventory_candidate')
sha=lambda p:hashlib.sha256(p.read_bytes()).hexdigest()
assert sha(OLD/'source/inventory.c')=='6d7ecec192b814ffd85805a3ea16ecf44f745e4b3d4a1674f8ad91468fe2f3df'
assert sha(OLD/'build/BOOTX64.EFI')=='7950e97739264a395b71aea450c33274a01b0ec5411ed9ec705a5b08bfa973e0'
assert sha(OLD/'build/SAGE1904-SPI-INVENTORY01.iso')=='7e023055a8c4e874d0e9d87a544ea948083705164b82eeafb439b1b46d8b3d8b'
for p in (OLD/'source').rglob('*'):
    if p.is_file():
        target=HERE/'source'/p.relative_to(OLD/'source');target.parent.mkdir(parents=True,exist_ok=True);shutil.copyfile(p,target)
for name in ['build_candidate.py','verify_candidate.py','verify_ovmf.py','finalize_report.py','sources.json']:
    shutil.copyfile(OLD/name,HERE/name)
path=HERE/'source/inventory.c';original=path.read_text(encoding='utf8');s=original
changes=[
 ('SPI-INVENTORY-01','SPI-INVENTORY-02'),
 ('PCI *chosen=0;unsigned matches=0;','PCI *chosen=0;unsigned matches=0;uint32_t chosen_id=0;'),
 ('if(id==0x7a248086&&seg==0&&bus==0&&dev==31&&fun==5){chosen=p;matches++;}',
  'if((id==0x7a248086||id==0x7aa48086)&&seg==0&&bus==0&&dev==31&&fun==5){chosen=p;chosen_id=id;matches++;}'),
 ('put("SPI_ID_GATE=8086:7A24_AT_0000:00:1F.5\\r\\n");',
  'put("SPI_ID_GATE=8086:");hex(chosen_id>>16,4);put("_AT_0000:00:1F.5\\r\\n");'),
 ('id!=0x7a248086','id!=chosen_id'),
 ('field("SPI_REV_CLASS",revclass,8);field("PCI_COMMAND_STATUS",command,8);',
  '/* 7AA4 is pinned to the revision/class actually observed in INV01.\n'
  '  * Both IDs use the same Linux INTEL_SPI_CNL register layout. */\n'
  ' if(id==0x7aa48086&&revclass!=0x0c800011){field("SPI_REV_CLASS",revclass,8);put("SPI_REV_CLASS_GATE=REJECTED\\r\\n");return ERR(3);}\n'
  ' field("SPI_REV_CLASS",revclass,8);field("PCI_COMMAND_STATUS",command,8);')]
for a,b in changes:
    assert a in s,a;s=s.replace(a,b)
path.write_text(s,encoding='utf8')
(HERE/'inventory01-to-02.patch').write_text(''.join(difflib.unified_diff(original.splitlines(True),s.splitlines(True),fromfile='INV01/source/inventory.c',tofile='INV02/source/inventory.c')),encoding='utf8')
for name in ['build_candidate.py','verify_ovmf.py','finalize_report.py']:
    path=HERE/name;s=path.read_text(encoding='utf8')
    for a,b in [('SPI-INVENTORY01','SPI-INVENTORY02'),('SPI-INVENTORY-01','SPI-INVENTORY-02'),('SPIINV01','SPIINV02'),('SPI INVENTORY 01','SPI INVENTORY 02'),('SPI inventory 01','SPI inventory 02')]:s=s.replace(a,b)
    s=s.replace('Only exact SAGE 1904 SMBIOS identity and Intel 7A24 at segment0:bus0:device31:function5.','Exact SAGE 1904 and Intel 7A24 or observed 7AA4 revision/class 0x0C800011 at segment0:bus0:device31:function5.')
    path.write_text(s,encoding='utf8')
path=HERE/'verify_candidate.py';s=path.read_text(encoding='utf8')
s=s.replace("8:0x0c800011","8:opt.get('revclass',0x0c800011)")
s=s.replace("vals[0]=0x7aa48086","vals[0]=opt.get('changed_id',0x7aa48086)")
s=s.replace("('unsupported_SPI_7AA4',{'id':0x7aa48086},3)","('unsupported_SPI_7AA5',{'id':0x7aa58086},3)")
anchor="(OUT/'synthetic-positive-log.txt').write_bytes(positive)"
assert anchor in s
extra='''
# INV01 has 62 baseline cases. Its unsupported-ID example now uses 7AA5;
# 7AA4 is intentionally supported only under the new observed class/revision gate.
assert len(cases)==62
test('7AA4_actual_revision_class_positive',id=0x7aa48086)
_,positive=execute('7AA4_QR_log',id=0x7aa48086)
test('7AA4_SMBIOS2_positive',id=0x7aa48086,sm=2)
for name,kw,status in [
 ('7AA4_unknown_revision',{'revclass':0x0c800012},3),
 ('7AA4_wrong_class',{'revclass':0x06010011},3),
 ('7AA4_wrong_location',{'function':4},3),
 ('7AA4_decode_disabled',{'command':0},3),
 ('7AA4_zero_BAR',{'bar':0},3),
 ('7AA4_64bit_BAR',{'bar':0xfe010004},3),
 ('7AA4_ID_changed_to_allowed_7A24',{'id_changes':True,'changed_id':0x7a248086},7),
 ('7AA4_ambiguous_handles',{'count':2},3)]:
    test(name,id=0x7aa48086,**kw,expected=ERR(status),no_mmio=True)
test('7AA4_wrong_vendor',id=0x7aa41234,expected=ERR(3),no_mmio=True)
test('7AA4_wrong_board_identity',id=0x7aa48086,board='Pro WS W790-ACE',expected=ERR(3),no_pci=True,no_mmio=True)
test('7AA4_busy_is_partial',id=0x7aa48086,busy=True,expected=ERR(7))
for offset in OFFSETS:test(f'7AA4_MMIO_read_failed_{offset:02x}',id=0x7aa48086,mmio_fail=offset,expected=ERR(7))
'''
s=s.replace(anchor,extra+'\n'+anchor)
s=s.replace("'case_count':len(cases)","'case_count':len(cases),'inv01_baseline_cases':62,'inv02_additional_cases':len(cases)-62")
path.write_text(s,encoding='utf8')
binding={'status':'PREPARED_ONLY','baseline_source_sha256':sha(OLD/'source/inventory.c'),'baseline_efi_sha256':sha(OLD/'build/BOOTX64.EFI'),'baseline_iso_sha256':sha(OLD/'build/SAGE1904-SPI-INVENTORY01.iso'),'new_source_sha256':sha(HERE/'source/inventory.c'),'diff_sha256':sha(HERE/'inventory01-to-02.patch'),'change_scope':'Add 7AA4 at observed revision/class 0x0C800011; retain exact selected-ID reread. No added register offsets or writes; INV02 labels only elsewhere.'}
(HERE/'preparation.json').write_text(json.dumps(binding,indent=2)+'\n',encoding='utf8')
print(json.dumps(binding,indent=2))
