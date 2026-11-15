from verify_observer import *
v=VM();print('initialize',hex(v.initialize()),'prepare',hex(v.prepare()));v.apply();v.publish_mode='good'
print('entry',hex(v.run('no_native_entry',v.tse_handle,v.st)),v.script_values,v.original_body)
