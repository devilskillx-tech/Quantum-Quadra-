"""Reject mandatory pytest suites that are empty, skipped or failing."""
import argparse
import xml.etree.ElementTree as ET


def verify(path, minimum=1):
    cases=ET.parse(path).getroot().findall('.//testcase')
    if len(cases)<minimum:
        raise ValueError(f'NO-GO missing tests: {len(cases)} < {minimum}')
    skipped=sum(len(c.findall('skipped')) for c in cases)
    failed=sum(len(c.findall('failure'))+len(c.findall('error')) for c in cases)
    if skipped or failed:
        raise ValueError(f'NO-GO skipped={skipped}, failed={failed}')
    return len(cases)


if __name__=='__main__':
    parser=argparse.ArgumentParser()
    parser.add_argument('path');parser.add_argument('--minimum',type=int,default=1)
    args=parser.parse_args()
    print(f'PASS {verify(args.path,args.minimum)} mandatory tests')
