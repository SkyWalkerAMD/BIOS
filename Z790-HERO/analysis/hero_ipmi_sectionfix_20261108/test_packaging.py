"""Regression checks against actual failing R2/P6 bodies, without rebuilding releases."""
from pathlib import Path
import ast, hashlib, json, sys
import build_sectionfix as sf

ROOT=sf.ROOT
results=[]
for relative,guid in [('analysis/hero_ipmi_r2/build.py','89924765-f984-4ad3-839b-51fdce378d88'),
                      ('analysis/hero_ipmi_p6_20261104/build_runtime.py','261135b0-7b73-49c0-bcc8-2f9cf4eef19e')]:
    source=ROOT/relative
    # Execute the exact two pure packaging functions from the real builder.
    tree=ast.parse(source.read_text())
    functions=[n for n in tree.body if isinstance(n,ast.FunctionDef) and n.name in ('section','section_stream')]
    assert len(functions)==2
    env={};exec(compile(ast.Module(body=functions,type_ignores=[]),str(source),'exec'),env)
    target=next(x for x in json.loads((ROOT/'analysis/hero_ipmi_r2_followup_20261108/dispatch-audit/container-targets.json').read_text()) if x['guid']==guid)
    original=(ROOT/target['path']/'body.bin').read_bytes()
    sections=sf.base.sections(original)
    rebuilt=env['section_stream']([(p[0],p[1]) for p in sections])
    assert rebuilt==original[:-2] and original[-2:]==b'\0\0'
    assert not sf.strict_end(original) and sf.strict_end(rebuilt)
    assert [x[2] for x in sf.base.sections(rebuilt)]==[x[2] for x in sections]
    for n in range(1,17):
        items=[(0x19,bytes(range(n))),(0x15,('X'*n+'\0').encode('utf-16-le'))]
        packed=env['section_stream'](items)
        assert sf.strict_end(packed)
        assert [(x[0],x[1]) for x in sf.base.sections(packed)]==items
        assert not sf.strict_end(packed+b'\0\0')
    results.append({'source':relative,'source_sha256':hashlib.sha256(source.read_bytes()).hexdigest(),
                    'actual_regression_passed':True,'alignment_cases_passed':16})
report={'passed':True,'builders':results,'firmware_flashing_performed':False,
        'independent_actual_machine_code_evidence':'../hero_ipmi_r2_followup_20261108/dispatch-audit/section-validation-machine-code.json'}
(sf.HERE/'packaging-tests.json').write_text(json.dumps(report,indent=2)+'\n')
print(json.dumps(report,indent=2))
