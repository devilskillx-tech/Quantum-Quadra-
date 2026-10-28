import sys
from pathlib import Path
import pytest
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'scripts'))
from assert_junit import verify


def test_skips_fail_closed(tmp_path):
    p=tmp_path/'out.xml'
    p.write_text('<testsuite><testcase name="x"><skipped/></testcase></testsuite>')
    with pytest.raises(ValueError,match='NO-GO'):verify(p)


def test_no_cases_fail_closed(tmp_path):
    p=tmp_path/'out.xml';p.write_text('<testsuite/>')
    with pytest.raises(ValueError,match='NO-GO'):verify(p)


def test_success_accepted(tmp_path):
    p=tmp_path/'out.xml';p.write_text('<testsuite><testcase name="x"/></testsuite>')
    assert verify(p)==1
