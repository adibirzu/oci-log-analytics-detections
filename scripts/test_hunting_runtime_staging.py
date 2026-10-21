"""Exercise the real staging script against an isolated generated runtime."""
import shutil
import subprocess
import os
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]

def test_runtime_stage_contains_hunting_freshness_inputs(tmp_path):
    script=tmp_path/'app/deploy/oke/stage-detections-runtime.sh'
    script.parent.mkdir(parents=True)
    shutil.copyfile(ROOT/'webapp/deploy/oke/stage-detections-runtime.sh',script)
    result=subprocess.run(['bash',str(script)],env={**os.environ,'LOGAN_DETECTIONS_REPO':str(ROOT)},capture_output=True,text=True)
    assert result.returncode==0,result.stderr
    runtime=tmp_path/'app/.logan-detections-runtime'
    for name in ['hunting_packs.json','hunting_reference_candidates.json','threat_intel_sources.json']:
        assert (runtime/'config'/name).is_file(),name
    import sys
    sys.path.insert(0,str(ROOT/'scripts'))
    from hunting_integrations.loader import load_bundle
    b=load_bundle(runtime/'queries/hunting_integration_bundle.json',root=runtime)
    assert len(b['queries'])==171
