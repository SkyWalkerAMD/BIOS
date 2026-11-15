from pathlib import Path
import json,hashlib
H=Path(__file__).resolve().parent
closed=json.loads((H/'rea/plan-tail.final-close.json').read_text());assert not closed.get('isError'),closed
source=(H/'rea_session.mjs').read_text()
source=source.replace("const output = path.join(here, 'rea');","const output = path.join(here, 'rea02');")
source=source.replace("fs.mkdirSync(path.join(runtime, 'tmp'), {recursive: true});","fs.mkdirSync(path.join(output, 'tmp'), {recursive: true});")
source=source.replace("TEMP: path.join(runtime, 'tmp'), TMP: path.join(runtime, 'tmp'),","TEMP: path.join(output, 'tmp'), TMP: path.join(output, 'tmp'),")
source=source.replace('cwd: runtime, env,',"cwd: path.resolve(here,'../../../..'), env,")
(H/'rea_session02.mjs').write_text(source)
(H/'rea_recovery.json').write_text(json.dumps({'prior':'rea/n08-fd18.json','prior_sha256':hashlib.sha256((H/'rea/n08-fd18.json').read_bytes()).hexdigest(),'cleanup_sha256':hashlib.sha256((H/'rea/plan-tail.final-close.json').read_bytes()).hexdigest(),'changes':['Run approved local REA/Ghidra command outside restricted local-loopback boundary','Separate owned rea02/tmp and root working directory as in successful sibling clients'],'unchanged':['original target and target SHA','600000ms startup deadline','120s decompiler deadline','read-only four-function query plan','no external network target or persistent configuration modification']},indent=2)+'\n')
