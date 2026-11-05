"""Seeded checks against deliberately simple independent reference algorithms."""
import random
import unittest
from dataclasses import replace
from datetime import datetime, timedelta
from authtrail.detection import investigate, distributed_success
from authtrail.incidents import group_incidents
from test_authtrail import event

class ReferenceTests(unittest.TestCase):
    def test_success_rules_against_list_reference(self):
        for seed in range(100):
            rng=random.Random(seed)
            records=[replace(event(0), timestamp=event(0).timestamp+timedelta(seconds=rng.randrange(60)),
                       host=f'h{rng.randrange(2)}', user=f'u{rng.randrange(2)}', source_ip=f'192.0.2.{rng.randrange(3)}',
                       outcome=rng.choice(['failed']*4+['accepted']),file='fixture',line=i,raw=str(i)) for i in range(100)]
            ordered=sorted(records,key=lambda e:(e.timestamp,e.outcome!='accepted',e.file,e.line))
            expected=[]; recent=[]
            for e in ordered:
                recent=[p for p in recent if (e.timestamp-p.timestamp).total_seconds()<=10]
                same=[p for p in recent if (p.host,p.user,p.source_ip)==(e.host,e.user,e.source_ip)]
                if e.outcome=='failed':recent.append(e)
                else:
                    if len(same)>=3:expected.append(tuple(p.raw for p in same+[e]))
                    recent=[p for p in recent if p not in same]
            actual=[tuple(e['raw'] for e in f['evidence']) for f in investigate(records,window=10,failures=3) if f['rule']=='success_after_failures']
            self.assertEqual(sorted(actual),sorted(expected),seed)
            expected=[];recent=[]
            for e in ordered:
                recent=[p for p in recent if (e.timestamp-p.timestamp).total_seconds()<=10]
                same=[p for p in recent if (p.host,p.user)==(e.host,e.user)]
                if e.outcome=='failed':recent.append(e)
                elif len(same)>=3 and len({p.source_ip for p in same})>=2:
                    expected.append(tuple(p.raw for p in same+[e]));recent=[p for p in recent if p not in same]
            actual=[tuple(e['raw'] for e in f['evidence']) for f in distributed_success(records,10,2,3)]
            self.assertEqual(sorted(actual),sorted(expected),seed)

    def test_grouping_against_pairwise_graph(self):
        for seed in range(100):
            rng=random.Random(seed);findings=[]
            for i in range(40):
                start=rng.randrange(100); end=start+rng.randrange(30)
                e=replace(event(0),user=f'u{rng.randrange(4)}',source_ip=f'192.0.2.{rng.randrange(4)}',file=str(i)).record()
                findings.append(dict(host=f'h{rng.randrange(2)}',start=(event(0).timestamp+timedelta(seconds=start)).isoformat(),
                    end=(event(0).timestamp+timedelta(seconds=end)).isoformat(),accounts=[e['user']],evidence=[e],severity='medium',rule='test'))
            for mode in ('source','account','either'):
                parent=list(range(len(findings)))
                def root(i):
                    while parent[i]!=i:i=parent[i]
                    return i
                for i,a in enumerate(findings):
                    for j,b in enumerate(findings[:i]):
                        distance=max((datetime.fromisoformat(a['start'])-datetime.fromisoformat(b['end'])).total_seconds(),(datetime.fromisoformat(b['start'])-datetime.fromisoformat(a['end'])).total_seconds(),0)
                        source=a['evidence'][0]['source_ip']==b['evidence'][0]['source_ip'];account=a['accounts']==b['accounts']
                        if a['host']==b['host'] and distance<=5 and ((mode in ('source','either') and source) or (mode in ('account','either') and account)):
                            parent[root(i)]=root(j)
                expected={frozenset(i for i in range(len(findings)) if root(i)==r) for r in {root(i) for i in range(len(findings))}}
                result=group_incidents(findings,5,mode)
                self.assertEqual({frozenset(g['finding_indexes']) for g in result},expected,(seed,mode))
                self.assertLessEqual(sum(len(g['relationships']) for g in result),len(findings)-len(result))
