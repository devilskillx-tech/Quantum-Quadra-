"""RTO/RPO gates for controlled synthetic recovery scenarios, not an SLA."""
from __future__ import annotations
import json
import os
import re
from dataclasses import asdict, dataclass
from pathlib import Path
from time import perf_counter


@dataclass(frozen=True)
class Observation:
    scenario: str
    rto_seconds: float
    rto_budget_seconds: float
    expected_cells: int
    recovered_cells: int
    lost_cells: int

    @property
    def passed(self) -> bool:
        return self.lost_cells == 0 and self.rto_seconds <= self.rto_budget_seconds

    def require_pass(self) -> None:
        if not self.passed:
            raise AssertionError(f'NO-GO {self.scenario}: RTO {self.rto_seconds}s '
                                 f'(budget {self.rto_budget_seconds}s); lost {self.lost_cells}')


def observe(name: str, start: float, expected: int, recovered: int, budget: float) -> Observation:
    if not re.fullmatch(r'[a-z0-9_-]{1,64}', name):
        raise ValueError('Invalid scenario name')
    if expected < 0 or recovered < 0 or budget <= 0:
        raise ValueError('Invalid measurement')
    record=Observation(name, round(max(0.0,perf_counter()-start),6),float(budget),
                       expected,recovered,max(0,expected-recovered))
    directory=os.getenv('QUADRA_RECOVERY_REPORT_DIR')
    if directory:
        root=Path(directory)
        root.mkdir(parents=True,exist_ok=True)
        tmp=root/(name+'.tmp')
        tmp.write_text(json.dumps({**asdict(record),'passed':record.passed},indent=2),encoding='utf-8')
        os.replace(tmp,root/(name+'.json'))
    return record
