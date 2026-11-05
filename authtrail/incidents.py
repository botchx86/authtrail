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
    # Per entity, the interval with the furthest end represents its connected
    # component. One real edge per entity suffices; avoid a dense pairwise graph.
    representatives = {}
    edges = []
    for i, f in sorted(enumerate(findings), key=lambda p: (datetime.fromisoformat(p[1]['start']), p[0])):
        start = datetime.fromisoformat(f['start'])
        end = datetime.fromisoformat(f['end'])
        sources = {e['source_ip'] for e in f['evidence']}
        accounts = set(f['accounts'])
        entities = []
        if group_by in ('source', 'either'):
            entities.extend(('source', value) for value in sorted(sources))
        if group_by in ('account', 'either'):
            entities.extend(('account', value) for value in sorted(accounts))
        for kind, value in entities:
            key = (f['host'], kind, value)
            previous = representatives.get(key)
            if previous and (start - previous[1]).total_seconds() <= gap:
                j, previous_end = previous
                if root(i) != root(j):
                    parents[root(i)] = root(j)
                    edges.append(dict(findings=[j, i], shared_sources=[value] if kind == 'source' else [],
                                      shared_accounts=[value] if kind == 'account' else []))
                if end > previous_end:
                    representatives[key] = (i, end)
            else:
                representatives[key] = (i, end)
    groups=defaultdict(list)
    for i in range(len(findings)): groups[root(i)].append(i)
    edges_by_group = defaultdict(list)
    for edge in edges:
        edges_by_group[root(edge['findings'][0])].append(edge)
    result=[]
    for number,indexes in enumerate(sorted(groups.values(),key=lambda g:(min(findings[i]['start'] for i in g),min(g))),1):
        selected=[findings[i] for i in indexes]; evidence={}
        for f in selected:
            for e in f['evidence']:
                evidence[(e['file'],e['line'],e['raw'])]=e
        timeline=sorted(evidence.values(),key=lambda e:(datetime.fromisoformat(e['timestamp']),e['file'],e['line']))
        result.append(dict(id=f'AT-{number:04d}',host=selected[0]['host'],start=min((f['start'] for f in selected), key=datetime.fromisoformat),
                           end=max((f['end'] for f in selected), key=datetime.fromisoformat),severity='high' if any(f['severity']=='high' for f in selected) else 'medium',
                           source_ips=sorted({e['source_ip'] for e in timeline}),accounts=sorted({a for f in selected for a in f['accounts']}),
                           finding_indexes=indexes,rules=sorted({f['rule'] for f in selected}),event_count=len(timeline),timeline=timeline,
                           relationships=edges_by_group[root(indexes[0])]))
    return result
