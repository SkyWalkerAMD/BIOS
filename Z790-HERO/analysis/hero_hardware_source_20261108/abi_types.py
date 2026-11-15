"""Host mirrors of the public typed contract (asserted against actual PE sizes)."""
import ctypes as C
U32=C.c_uint32;U64=C.c_uint64;PTR=C.c_void_p
class PathView(C.Structure):
 _fields_=[(n,U64) for n in ('protocol_status','pointer','first_status','second_status')]+[(n,U32) for n in ('first_bytes','second_bytes','first_crc32','second_crc32','valid','stable')]+[('first',PTR),('second',PTR)]
class PciView(C.Structure):
 _fields_=[(n,U64) for n in ('location_status','config_status','segment','bus','device','function')]+[(n,U32) for n in ('flags','config_bytes','config_crc32','reserved')]+[('config',PTR)]
class BlockView(C.Structure):
 _fields_=[(n,U64) for n in ('revision','media_pointer','revision_after','media_pointer_after')]+[(n,U32) for n in ('media_bytes','readable','stable','reserved')]+[('first',PTR),('second',PTR)]
class DiskView(C.Structure):
 _fields_=[('interface_guid_le',C.c_uint8*16),('identify_status',U64)]+[(n,U32) for n in ('expected_bytes','returned_bytes','captured_bytes','crc32','allowlisted','skip','buffer_guards_ok','format_size_match')]+[('identify',PTR)]
class Data(C.Union):_fields_=[('pci',PciView),('block',BlockView),('disk',DiskView)]
class Record(C.Structure):
 _fields_=[(n,U32) for n in ('version','bytes','kind','source_index')]+[(n,U64) for n in ('source_handle','protocol_status','protocol_pointer')]+[(n,U32) for n in ('protocol_readable','valid','incomplete','issues')]+[('path',PathView),('data',Data)]
class Group(C.Structure):
 _fields_=[(n,U32) for n in ('kind','limit','captured','valid_records','complete','stable','truncated','incomplete_records')]+[(n,U64) for n in ('enum_status','declared','cleanup_status','memory_map_status','memory_map_bytes','descriptor_bytes')]+[(n,U32) for n in ('memory_map_version','reserved_map','issues','reserved')]+[('source_bytes',U64),('source_crc32',U32),('reserved2',U32)]
class Result(C.Structure):
 _fields_=[(n,U32) for n in ('version','bytes','complete','incomplete','visitor_calls','visitor_aborted')]+[('reserved',U32*2),('status',U64),('groups',Group*3)]
VISIT=C.CFUNCTYPE(C.c_int,PTR,C.POINTER(Record))
class Visitor(C.Structure):_fields_=[('version',U32),('bytes',U32),('user',PTR),('visit',VISIT)]
class HpcRecord(C.Structure):
 _fields_=[(n,U32) for n in ('source_index','flags','config_crc32','path_crc32','path_bytes','reserved')]+[('source_handle',U64),('segment',C.c_uint16),('bus',C.c_uint8),('device',C.c_uint8),('function',C.c_uint8),('pad',C.c_uint8*3),('config',C.c_uint8*256),('path',C.c_uint8*1024)]
class Sink(C.Structure):_fields_=[('records',C.POINTER(HpcRecord))]+[(n,U32) for n in ('capacity','used','rejected','reserved')]
class Capture(C.Structure):
 _fields_=[(n,U32) for n in ('version','pci_declared','pci_captured','pci_complete','pci_truncated','reserved')]+[('pci_status',U64),('cleanup_status',U64),('source_crc32',U32),('source_bytes',U32)]
