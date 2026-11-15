from pathlib import Path
HERE=Path(__file__).resolve().parent
base=HERE.parent/'spi_descriptor_candidate02/verify_ovmf.py'
text=base.read_text(encoding='utf-8')
text=text.replace('SAGE1904-SPI-DESCRIPTOR02.iso','SAGE1904-MEDIA-WRITEBACK01.iso')
text=text.replace("'-device','ide-cd,drive=cd,bus=ide.0,bootindex=1'", "'-device','qemu-xhci,id=xhci','-device','usb-storage,bus=xhci.0,drive=cd,bootindex=1'")
text=text.replace("from decode_captures import read_image,parse_frame,assemble", "from decode_captures import read_image,parse_frame,assemble\nsys.path[:0]=[str(ROOT/'tools/pydeps'),str(ROOT/'tools/vm-pydeps')]\nfrom pyfatfs.PyFatFS import PyFatFS")
start=text.index("    if identity=='synthetic_sage':")
end=text.index("    save(folder/'command.json',args)",start)
text=text[:start]+'''    pristine=HERE.parent/'media_writeback_review/blank_test/WRITEBACK02.img'
    assert sha(pristine)=='df7fa016a0f4be496d3d446db558e8de15f537aa9953faff20b4ae0c6132b4b6'
    datafiles=[];before_hashes={}
    if identity!='absent':
        for index in range(2 if identity=='duplicate' else 1):
            disk=folder/f'data-{index}.img';shutil.copyfile(pristine,disk)
            if identity in ['wrong_marker','existing_result']:
                with PyFatFS(str(disk),utc=True) as fs:
                    if identity=='wrong_marker':fs.writebytes('/IDENTIFY.TXT',b'WRONG TEST MARKER')
                    else:fs.writebytes('/WRBACK.TXT',b'EXISTING CONTENT MUST SURVIVE')
            before_hashes[str(disk)]=sha(disk);datafiles.append(disk)
            args+=['-drive',f'if=none,id=wb{index},format=raw,file='+str(disk)+(',readonly=on' if identity=='readonly' else '')]
            if identity=='non_usb':args+=['-device',f'virtio-blk-pci,drive=wb{index}']
            else:
                args+=['-device',f'usb-storage,bus=xhci.0,drive=wb{index}']
''' + text[end:]
start=text.index("            assert b'DESCRIPTOR_DATA_NOT_EXPORTED'")
end=text.index("            key('home');",start)
text=text[:start]+'''            expected_success=identity=='positive'
            assert (b'TEST_STATUS=0x0000000000000000' in log)==expected_success,log.decode('ascii')
            if expected_success:
                assert b'UEFI_FILE_READBACK_STATUS=0x0000000000000000' in log
                assert b'EXACT_MATCHES=0x0000000000000001' in log
            else:assert b'FILE_WRITE_STATUS' not in log
''' + text[end:]
text=text.replace("wait(b'Descriptor log ended.',before)","wait(b'File test ended.',before)")
needle="            assert sha(ISO)==result['iso_sha256']"
text=text.replace(needle,needle+'''
            for disk in datafiles:
                assert disk.stat().st_size==16777216
                with PyFatFS(str(disk),read_only=True,utc=True) as fs:
                    if identity=='positive':
                        assert fs.readbytes('/WRBACK.TXT')==(HERE/'expected-result.bin').read_bytes()
                        assert hashlib.sha256(fs.readbytes('/IDENTIFY.TXT')).hexdigest()=='cf23bdeea12a51328c1589210a11591a249964372d7aac3da93de75fbae5230a'
                        assert set(fs.listdir('/'))=={'IDENTIFY.TXT','WRBACK.TXT'}
                    else:assert sha(disk)==before_hashes[str(disk)],'Noneligible image changed'
            result['disposable_image_paths']=[str(p) for p in datafiles]
            result['positive_disk_reopened_read_only_and_exact_file_verified']=expected_success
            result['noneligible_images_unchanged']=not expected_success
''')
text=text.replace("'identity_and_missing_controller_gate'","'USB_geometry_label_marker_unique_selection_and_bounded_file_readback'")
text=text.replace('no_writable_data_drive=True','only_disposable_regular_file_drives=True')
text=text.replace("cases=[run('default'),run('synthetic_sage')]","cases=[run(name) for name in (sys.argv[1:] or ['positive','absent','wrong_marker','existing_result','readonly','duplicate','non_usb'])]")
start=text.index('"""');end=text.index('"""',start+3)+3
text='"""Actual OVMF file operations on disposable local USB IMG copies; no hardware or network.\nComplete QR roundtrip, refusal cases and local image reopening are checked.\n"""'+text[end:]
(HERE/'verify_ovmf.py').write_text(text,encoding='utf-8')
print('Prepared seven file-writeback OVMF cases.')
