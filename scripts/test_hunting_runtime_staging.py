"""Exercise the real staging script against an isolated generated runtime."""
import shutil
import subprocess
import os
import sys

import pytest
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


@pytest.mark.parametrize(('name', 'fails', 'signal_move', 'fault_signal'), [
    ('success', '', '', 'TERM'),
    ('initial-rename-fails', '1', '', 'TERM'),
    ('replacement-fails', '2', '', 'TERM'),
    ('restoration-fails', '2,3', '', 'TERM'),
    ('term-after-backup', '', '1', 'TERM'),
    ('int-after-backup', '', '1', 'INT'),
    ('hup-after-backup', '', '1', 'HUP'),
    ('term-after-replacement', '', '2', 'TERM'),
])
def test_runtime_stage_preserves_previous_on_rename_failure_or_signal(
    tmp_path, name, fails, signal_move, fault_signal,
):
    """The executable stager must retain the last runtime through swap faults."""
    # Only the generator is stubbed: exercise real shell swaps, traps and cleanup.
    source = tmp_path / 'source'
    required = {
        'queries': ['logan_ql_reference_catalog.json', 'cross_ql_mapping_patterns.json',
                    'conversion_examples.json', 'forge_detection_catalog.json',
                    'catalog.json', 'hunting_integration_bundle.json',
                    'dashboard_inventory.json', 'siem_log_examples.json'],
        'config': ['hunting_packs.json', 'hunting_reference_candidates.json',
                   'threat_intel_sources.json', 'sigma_oci_mapping.yaml', 'mapping/_root.yaml'],
        'test_data': ['manifest.json'],
        'scripts': ['logan_workbench_convert.py', 'build_orm_stack.py'],
        'stack': ['main.tf'],
    }
    for directory, names in required.items():
        for filename in names:
            path = source / directory / filename
            path.parent.mkdir(parents=True, exist_ok=True)
            path.touch()
    tools = tmp_path / 'bin'
    tools.mkdir()
    generator = tools / 'python3'
    generator.write_text('#!/bin/bash\nmkdir -p -- "$3"\nprintf new > "$3/marker"\n')
    generator.chmod(0o755)
    mover = tools / 'mv'
    mover.write_text('''#!/bin/bash
count=0
[[ ! -f "$MV_COUNT" ]] || read -r count < "$MV_COUNT"
count=$((count + 1))
printf '%s\\n' "$count" > "$MV_COUNT"
case ",$FAIL_MOVES," in
  *,$count,*) exit 74 ;;
esac
/bin/mv "$@" || exit $?
if [[ "$SIGNAL_MOVE" == "$count" ]]; then
  kill -s "$FAULT_SIGNAL" "$PPID"
fi
''')
    mover.chmod(0o755)
    app = tmp_path / name
    script = app / 'deploy/oke/stage-detections-runtime.sh'
    script.parent.mkdir(parents=True)
    shutil.copyfile(ROOT / 'webapp/deploy/oke/stage-detections-runtime.sh', script)
    runtime = app / '.logan-detections-runtime'
    runtime.mkdir()
    (runtime / 'marker').write_text('previous')
    env = {'PATH': str(tools) + os.pathsep + os.environ['PATH'],
           'LOGAN_DETECTIONS_REPO': str(source), 'MV_COUNT': str(app / 'mv-count'),
           'FAIL_MOVES': fails, 'SIGNAL_MOVE': signal_move, 'FAULT_SIGNAL': fault_signal}
    result = subprocess.run(['bash', str(script)], env=env, capture_output=True,
                            text=True, timeout=30)
    if name == 'success':
        assert result.returncode == 0, result.stderr
        assert (runtime / 'marker').read_text() == 'new'
    else:
        assert result.returncode != 0, name
        survivors = [p for p in app.rglob('marker') if p.read_text() == 'previous']
        assert len(survivors) == 1, (name, result.stderr, survivors)
        if name in ('restoration-fails', 'term-after-replacement'):
            assert str(survivors[0].parent) in result.stderr
        elif not signal_move or signal_move == '1':
            assert survivors[0] == runtime / 'marker', name
    if name not in ('restoration-fails', 'term-after-replacement'):
        assert not list(app.glob('.logan-detections-stage.*')), name
