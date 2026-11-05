import html
import json

def render_html(report):
    esc = lambda value: html.escape(str(value), quote=True)
    cards = []
    for item in report['findings']:
        rows = ''.join('<tr>' + ''.join(f'<td>{esc(event[key])}</td>' for key in
                       ('timestamp', 'user', 'outcome', 'method', 'file', 'line', 'raw')) + '</tr>'
                       for event in item['evidence'])
        cards.append(f"<article><h2>{esc(item['severity'].upper())} · {esc(item['rule'])}</h2>"
                     f"<p>{esc(item['host'])} ← {esc(item.get('source_ip') or ', '.join(item['source_ips']))}</p><p>{esc(item['explanation'])}</p>"
                     f'<details><summary>{len(item["evidence"])} evidence events</summary><div class="scroll"><table>'
                     '<tr><th>UTC time</th><th>Account</th><th>Outcome</th><th>Method</th><th>File</th><th>Line</th><th>Original log</th></tr>'
                     f'{rows}</table></div></details></article>')
    investigations = []
    for incident in report.get('incidents', []):
        rows = ''.join('<tr>' + ''.join(f'<td>{esc(event[key])}</td>' for key in
                       ('timestamp', 'source_ip', 'user', 'outcome', 'file', 'line', 'raw')) + '</tr>'
                       for event in incident['timeline'])
        investigations.append(f"<article><h2>{esc(incident['id'])} · {esc(incident['host'])}</h2>"
                              f"<p>{esc(incident['severity'].upper())} · {esc(', '.join(incident['rules']))}</p>"
                              f"<p>{esc(incident['start'])} to {esc(incident['end'])}</p>"
                              f'<details><summary>{incident["event_count"]} unique timeline events</summary>'
                              '<div class="scroll"><table><tr><th>UTC time</th><th>Source</th><th>Account</th>'
                              '<th>Outcome</th><th>File</th><th>Line</th><th>Original log</th></tr>'
                              f'{rows}</table></div></details></article>')
    return ('<!doctype html><html lang="en"><meta charset="utf-8"><meta name="viewport" content="width=device-width">'
            '<title>AuthTrail investigation</title><style>body{font:16px system-ui;max-width:1100px;margin:40px auto;padding:0 20px;background:#101827;color:#e5edf7}'
            'article{background:#1c2940;padding:20px;margin:16px 0;border-radius:10px}h1{color:#65dbc7}td,th{text-align:left;padding:9px;border-bottom:1px solid #43516a}'
            '.scroll{overflow:auto}td{vertical-align:top}summary{cursor:pointer}</style><h1>AuthTrail</h1>'
            f'<p>{report["stats"]["parsed"]} authentication events · {len(cards)} findings · timestamps in UTC</p>'
            '<p>Findings are investigation leads, not proof of compromise.</p>'
            f'<p>Run configuration: {esc(json.dumps(report["configuration"]))}</p>'
            f'<p>Input statistics: {esc(json.dumps(report["stats"]))}</p>'
            f'<p>Input files: {esc(json.dumps(report.get("input_files", [])))}</p>'
            f'<p>Parse diagnostics (up to 20): {esc(json.dumps(report.get("diagnostics", [])))}</p>'
            + ('<h2>Grouped investigations</h2>' + ''.join(investigations) if investigations else '')
            + '<h2>Individual findings</h2>' + ''.join(cards) + ('<p>No findings matched the configured thresholds.</p>' if not cards else '') + '</html>')



def compact_report(report):
    """Schema 4 stores unique event objects and references them from findings."""
    result = dict(report, schema_version=4)
    events = {}
    def refs(records):
        for record in records:
            events[record['id']] = record
        return [record['id'] for record in records]
    result['findings'] = [dict({k:v for k,v in f.items() if k != 'evidence'},
                               evidence_ids=refs(f['evidence'])) for f in report['findings']]
    result['incidents'] = [dict({k:v for k,v in i.items() if k != 'timeline'},
                                timeline_ids=refs(i['timeline'])) for i in report['incidents']]
    result['events'] = events
    return result
