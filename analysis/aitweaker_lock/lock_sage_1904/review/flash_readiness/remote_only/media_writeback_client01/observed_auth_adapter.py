"""Accept the target's observed zero-metadata F1 only while awaiting auth.

The original protocol engine remains unchanged. Ordinary disk frames still
pass its original header, instance, command, range and payload checks.
"""
import struct
from hdmedia_offline import IUSBEngine

class ObservedAuthEngine(IUSBEngine):
    def handle(self,frame):
        legacy=(isinstance(frame,bytes) and len(frame)==108 and frame[:8]==b'IUSB    '
                and frame[8:11]==b'\0\0\0' and frame[17:20]==b'\0\0\0'
                and struct.unpack_from('<I',frame,12)[0]==76
                and frame[41]==0xf1 and frame[62]==1)
        if self.state=='AUTH_PENDING' and legacy:
            try:
                self.instance=frame[23]
                self.image=self.factory()
                self.state='ACTIVE'
                return None
            except Exception:
                self.stop();raise
        return super().handle(frame)

def public_frame_fields(frame):
    """Only fixed protocol metadata, excluding token, key and other-user IP."""
    if len(frame)<32 or frame[:8]!=b'IUSB    ':return {'header_signature_matches':False,'bytes':len(frame)}
    return {'bytes':len(frame),'version':list(frame[8:10]),'header_length':frame[10],
            'device_type':frame[17],'protocol':frame[18],'direction':frame[19],
            'instance':frame[23],'payload_length':struct.unpack_from('<I',frame,12)[0],
            'opcode':f'{frame[41]:02X}' if len(frame)>41 else None}
