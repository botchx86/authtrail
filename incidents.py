"""Group related findings into deterministic, deduplicated timelines."""
from datetime import datetime


def group_incidents(findings, gap=300):
    # Merge temporal components on the same host when a source or account overlaps.
    # Transitive relationships can join multiple components; unrelated users and
    # sources on a busy host remain separate.
    components = []
    severity_order = {'medium': 1, 'high': 2}
    for index, finding in sorted(enumerate(findings), key=lambda pair: (pair[1]['start'], pair[0])):
        sources = {e['source_ip'] for e in finding['evidence']}
        accounts = set(finding['accounts'])
        start, end = datetime.fromisoformat(finding['start']), datetime.fromisoformat(finding['end'])
        current = dict(host=finding['host'], sources=sources, accounts=accounts,
                       start=start, end=end, indexes=[index])
        changed = True
        while changed:
            changed = False
            for component in list(components):
                distance = max((current['start'] - component['end']).total_seconds(),
                               (component['start'] - current['end']).total_seconds(), 0)
                if (component['host'] == current['host'] and distance <= gap and
                    (component['sources'] & current['sources'] or component['accounts'] & current['accounts'])):
                    current['sources'] |= component['sources']
                    current['accounts'] |= component['accounts']
                    current['start'] = min(current['start'], component['start'])
                    current['end'] = max(current['end'], component['end'])
                    current['indexes'] += component['indexes']
                    components.remove(component)
                    changed = True
        components.append(current)
    incidents = []
    for number, component in enumerate(sorted(components, key=lambda c: (c['start'], c['host'], min(c['indexes']))), 1):
        selected = [findings[i] for i in sorted(component['indexes'])]
        evidence = {}
        for finding in selected:
            for event in finding['evidence']:
                evidence[(event['timestamp'], event['host'], event['raw'])] = event
        timeline = sorted(evidence.values(), key=lambda e: (e['timestamp'], e['file'], e['line']))
        incidents.append(dict(id=f'AT-{number:04d}', host=component['host'],
                              start=component['start'].isoformat(), end=component['end'].isoformat(),
                              severity=max((f['severity'] for f in selected), key=severity_order.get),
                              source_ips=sorted(component['sources']), accounts=sorted(component['accounts']),
                              finding_indexes=sorted(component['indexes']), rules=sorted({f['rule'] for f in selected}),
                              event_count=len(timeline), timeline=timeline))
    return incidents
