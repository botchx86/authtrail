"""Group using explicit finding-to-finding relationships within a host/time index."""
from collections import defaultdict
from datetime import datetime


def group_incidents(findings, gap=300, group_by='source'):
    if gap < 0 or group_by not in ('source', 'account', 'either'):
        raise ValueError('invalid grouping settings')
    parents=list(range(len(findings)))
    def root(i):
        while parents[i] != i:
            parents[i]=parents[parents[i]]; i=parents[i]
        return i
    active=defaultdict(list); edges=[]
    for i,f in sorted(enumerate(findings),key=lambda p: p[1]['start']):
        start=datetime.fromisoformat(f['start']); end=datetime.fromisoformat(f['end'])
        sources={e['source_ip'] for e in f['evidence']}; accounts=set(f['accounts'])
        host=active[f['host']]
        host[:]=[x for x in host if (start-x[1]).total_seconds() <= gap]
        for j,_,other_sources,other_accounts in host:
            shared_sources=sources & other_sources; shared_accounts=accounts & other_accounts
            if (group_by in ('source','either') and shared_sources) or (group_by in ('account','either') and shared_accounts):
                parents[root(i)]=root(j)
                edges.append(dict(findings=[j,i],shared_sources=sorted(shared_sources),shared_accounts=sorted(shared_accounts)))
        host.append((i,end,sources,accounts))
    groups=defaultdict(list)
    for i in range(len(findings)): groups[root(i)].append(i)
    result=[]
    for number,indexes in enumerate(sorted(groups.values(),key=lambda g:(min(findings[i]['start'] for i in g),min(g))),1):
        selected=[findings[i] for i in indexes]; evidence={}
        for f in selected:
            for e in f['evidence']:
                evidence[(e['file'],e['line'],e['raw'])]=e
        timeline=sorted(evidence.values(),key=lambda e:(datetime.fromisoformat(e['timestamp']),e['file'],e['line']))
        result.append(dict(id=f'AT-{number:04d}',host=selected[0]['host'],start=min(f['start'] for f in selected),
                           end=max(f['end'] for f in selected),severity='high' if any(f['severity']=='high' for f in selected) else 'medium',
                           source_ips=sorted({e['source_ip'] for e in timeline}),accounts=sorted({a for f in selected for a in f['accounts']}),
                           finding_indexes=indexes,rules=sorted({f['rule'] for f in selected}),event_count=len(timeline),timeline=timeline,
                           relationships=[edge for edge in edges if edge['findings'][0] in indexes]))
    return result
