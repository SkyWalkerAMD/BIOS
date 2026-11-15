"""Create a separate observer; retain all frozen helper logic unchanged."""
from pathlib import Path
import hashlib,json,difflib
HERE=Path(__file__).resolve().parent
HD=HERE.parent/'media_writeback_client01';HW=HERE.parents[3]/'remote_172_20_2_162'
old=(HD/'live_writeback03.py').read_text(encoding='utf8')
assert hashlib.sha256((HD/'live_writeback03.py').read_bytes()).hexdigest()=='ce467a46d9c15c657e60cc0c9ebdd2c081229b722e32a6d322e74d9963efc072'
new=old.replace('Parent-controlled temporary HDMEDIA for the sole pinned disposable IMG.',
                'Same pinned temporary HDMEDIA plus redacted outgoing capacity observation.')
new=new.replace("'frames':0,'opcode_counts':{},'socket_closed':False",
                "'frames':0,'opcode_counts':{},'capacity_sends':[],'socket_closed':False")
before='if response is not None:sock.sendall(response)'
after="""if response is not None:
                            sock.sendall(response)
                            if frame[41]==0x25:
                                exact=(len(response)==101 and response[:8]==b'IUSB    ' and response[41]==0x25 and response[61:69]==bytes.fromhex('00007fff00000200'))
                                # Log only public metadata and the exact expected capacity.
                                # Never save whole frames, auth headers, keys or tokens.
                                report['capacity_sends'].append({'utc':datetime.now(timezone.utc).isoformat(),'frame_bytes':len(response),'sendall_returned':True,'expected_capacity_bytes_match':exact,'capacity8_hex':response[61:69].hex() if exact else None,'fields':public_frame_fields(response)})"""
assert old.count(before)==1
new=new.replace(before,after)
target=HD/'live_writeback04.py';assert not target.exists()
target.write_text(new,encoding='utf8',newline='\n')
operation=HW/'operations/hdmedia_writeback04_session.mjs';assert not operation.exists()
opold=(HW/'operations/hdmedia_writeback03_session.mjs').read_text(encoding='utf8')
assert opold.count('live_writeback03.py')==1
operation.write_text(opold.replace('live_writeback03.py','live_writeback04.py'),encoding='utf8',newline='\n')
compile(new,str(target),'exec')
record={'scope':'Only outgoing capacity metadata observation; original helper and operation remain unchanged.',
        'helper_sha256':hashlib.sha256(target.read_bytes()).hexdigest(),
        'operation_sha256':hashlib.sha256(operation.read_bytes()).hexdigest(),
        'diff':'\n'.join(difflib.unified_diff(old.splitlines(),new.splitlines(),fromfile='live_writeback03.py',tofile='live_writeback04.py'))}
(HERE/'capacity_observer_delta.json').write_text(json.dumps(record,indent=2)+'\n')
print(json.dumps(record,indent=2))
