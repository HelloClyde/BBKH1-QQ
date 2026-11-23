"""Create a per-device identity on a mounted H1 disk; preserve existing data."""
import argparse
from pathlib import Path
import sys
ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'h1-qq-native/tools'))
from identity_format import make_record,parse_record
def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--root',required=True,type=Path,help='Mounted H1 disk root, for example E:/')
    p.add_argument('--utc-offset',type=int,default=480,help='H1 RTC local timezone in minutes; default UTC+8')
    a=p.parse_args()
    if not -840<=a.utc_offset<=840:p.error('UTC offset must be between -840 and 840 minutes')
    base=a.root.resolve()
    if not base.is_dir():p.error('Mounted disk root does not exist')
    target=base/'应用/数据/QQ/H1QQ.ID';target.parent.mkdir(parents=True,exist_ok=True)
    if target.exists():
        parse_record(target.read_bytes());print('Existing identity preserved; no files replaced.');return
    data=make_record(offset=a.utc_offset,clock_adjustment=0)
    # Exclusive creation prevents replacing another process's initialized key.
    with target.open('xb') as f:f.write(data)
    if target.read_bytes()!=data:raise RuntimeError('Identity readback mismatch')
    print('Created one unique device identity. Keep H1 date/time accurate; retain the data directory for upgrades.')
if __name__=='__main__':main()
