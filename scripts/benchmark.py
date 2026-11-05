"""Synthetic full-pipeline benchmark; invoke from the repository root."""
import argparse
from datetime import datetime, timedelta, timezone
from pathlib import Path
import subprocess
import sys
import tempfile
import time

p=argparse.ArgumentParser();p.add_argument('--events',type=int,default=100000);args=p.parse_args()
with tempfile.TemporaryDirectory() as tmp:
    log=Path(tmp)/'auth.log'; report=Path(tmp)/'report.json'
    base=datetime(2026,1,1,tzinfo=timezone.utc)
    with log.open('w') as f:
        for i in range(args.events):
            f.write(f'{(base+timedelta(milliseconds=i)).isoformat()} host sshd[{i}]: Failed password for user{i%20} from 192.0.2.{i%10+1} port 22 ssh2\n')
    start=time.perf_counter()
    subprocess.run([sys.executable,'-m','authtrail',str(log),'--year','2026','--compact-json','--max-events',str(args.events),'--json',str(report)],check=True,stdout=subprocess.DEVNULL)
    print(f'{args.events} events: {time.perf_counter()-start:.2f}s; JSON {report.stat().st_size/1024/1024:.1f} MiB')
