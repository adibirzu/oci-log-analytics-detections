import sys
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parent))

def test_release_checks_hunting_after_catalog_and_dictionary():
    from release_checklist import build_steps
    steps=build_steps(include_live=False,skip_tests=True,lookback='1d',query_timeout=30)
    names=[s[0] for s in steps]
    assert 'hunting integration bundle generation' in names
    assert 'hunting integration bundle freshness' in names
    gen=names.index('hunting integration bundle generation')
    assert gen>names.index('catalog generation')
    assert gen>names.index('field dictionary validation')
    assert gen>names.index('dashboard inventory export')
    check=steps[names.index('hunting integration bundle freshness')][1]
    assert '--check' in check
