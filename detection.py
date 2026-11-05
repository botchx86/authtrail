"""Sliding-window detection with incremental counts and complete burst evidence."""
from collections import Counter, defaultdict, deque


def investigate(events, window=300, failures=5, users=5):
    from .cli import finding
    if min(window, failures, users) < 1:
        raise ValueError('window and thresholds must be positive')
    groups = defaultdict(list)
    for event in events:
        groups[event.host, event.source_ip].append(event)
    results = []
    for (host, source), records in sorted(groups.items()):
        recent = deque()
        accounts = defaultdict(deque)
        counts = Counter()
        active = {}

        def close(key):
            burst = active.pop(key, None)
            if burst:
                results.append(finding(key[0], 'medium', host, source, burst['events'],
                                       burst['explanation'], burst['triggered_at']))

        def update(key, seed, event, explanation):
            if key not in active:
                active[key] = dict(events=list(seed), triggered_at=event.timestamp.isoformat(), explanation=explanation)
            else:
                active[key]['events'].append(event)

        for event in sorted(records, key=lambda item: item.timestamp):
            while recent and (event.timestamp - recent[0].timestamp).total_seconds() > window:
                old = recent.popleft()
                # Successful logins may have cleared this account since insertion.
                queue = accounts.get(old.user)
                if queue and queue[0] is old:
                    queue.popleft()
                    counts[old.user] -= 1
                    if counts[old.user] < failures:
                        close(('repeated_failures', old.user))
                    if not counts[old.user]:
                        del counts[old.user]
                        del accounts[old.user]
                    if len(counts) < users:
                        close(('many_accounts', ''))
            account = accounts.get(event.user, ())
            if event.outcome == 'accepted':
                if len(account) >= failures:
                    results.append(finding('success_after_failures', 'high', host, source,
                                           list(account) + [event],
                                           'Successful login after repeated failures; verify whether expected.'))
                close(('repeated_failures', event.user))
                accounts.pop(event.user, None)
                counts.pop(event.user, None)
                if len(counts) < users:
                    close(('many_accounts', ''))
                continue
            recent.append(event)
            accounts[event.user].append(event)
            counts[event.user] += 1
            if counts[event.user] >= failures:
                update(('repeated_failures', event.user), accounts[event.user], event,
                       'Repeated failures against one account.')
            if len(counts) >= users:
                # Only materialize the rolling window when opening a burst.
                key = ('many_accounts', '')
                valid = {id(item) for queue in accounts.values() for item in queue} if key not in active else set()
                seed = (item for item in recent if id(item) in valid) if key not in active else ()
                update(key, seed, event,
                       'One source attempted multiple accounts; possible account enumeration or password spraying.')
        for key in list(active):
            close(key)
    return sorted(results, key=lambda item: (item['end'], item['rule'], item['host'], item['source_ip']))


def investigate_distributed(events, window=300, sources=5, failures=10):
    """Find concurrent failures across sources per host and per host/account."""
    from .cli import finding
    if min(window, sources, failures) < 1:
        raise ValueError('distributed window and thresholds must be positive')
    groups = defaultdict(list)
    for event in events:
        if event.outcome == 'failed':
            groups[(event.host, None)].append(event)
            groups[(event.host, event.user)].append(event)
    results = []
    for (host, account), records in groups.items():
        recent, counts = deque(), Counter()
        burst, triggered = None, None
        rule = 'distributed_account' if account is not None else 'distributed_host'

        def emit():
            item = finding(rule, 'medium', host, None, burst,
                           'Multiple sources generated authentication failures against ' +
                           ('one account.' if account is not None else 'one host.') +
                           ' Investigate shared infrastructure and expected automation.', triggered)
            item['source_ips'] = sorted({e.source_ip for e in burst})
            results.append(item)

        for event in sorted(records, key=lambda e: e.timestamp):
            while recent and (event.timestamp - recent[0].timestamp).total_seconds() > window:
                old = recent.popleft()
                counts[old.source_ip] -= 1
                if not counts[old.source_ip]:
                    del counts[old.source_ip]
                if burst is not None and (len(recent) < failures or len(counts) < sources):
                    emit()
                    burst = None
            recent.append(event)
            counts[event.source_ip] += 1
            if len(recent) >= failures and len(counts) >= sources:
                if burst is None:
                    burst, triggered = list(recent), event.timestamp.isoformat()
                else:
                    burst.append(event)
        if burst is not None:
            emit()
    return sorted(results, key=lambda f: (f['end'], f['host'], f['rule'], f['accounts']))
