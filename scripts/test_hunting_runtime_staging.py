"""Exercise the real staging script against an isolated generated runtime."""
import shutil
import subprocess
import os
import sys
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'scripts'))

def test_runtime_stage_contains_hunting_freshness_inputs(tmp_path):
    from build_orm_stack import stage_runtime
    source = tmp_path / 'source'
    stage_runtime(ROOT, source)
    (source / 'test_data').mkdir()
    (source / 'test_data/manifest.json').write_text('{"synthetic": true}')
    script=tmp_path/'app/deploy/oke/stage-detections-runtime.sh'
    script.parent.mkdir(parents=True)
    shutil.copyfile(ROOT/'webapp/deploy/oke/stage-detections-runtime.sh',script)
    env = {name: os.environ[name] for name in ('HOME', 'PATH') if name in os.environ}
    env.update(LOGAN_DETECTIONS_REPO=str(source), PYTHON_DOTENV_DISABLED='true', PYTHONDONTWRITEBYTECODE='1')
    result=subprocess.run(['bash',str(script)],env=env,capture_output=True,text=True,timeout=30)
    assert result.returncode==0,result.stderr
    runtime=tmp_path/'app/.logan-detections-runtime'
    for name in ['hunting_packs.json','hunting_reference_candidates.json','threat_intel_sources.json']:
        assert (runtime/'config'/name).is_file(),name
    from hunting_integrations.loader import load_bundle
    b=load_bundle(runtime/'queries/hunting_integration_bundle.json',root=runtime)
    assert len(b['queries'])==171
