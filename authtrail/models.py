from dataclasses import dataclass, asdict
from datetime import datetime
import hashlib

@dataclass(frozen=True)
class Event:
    timestamp: datetime
    host: str
    user: str
    source_ip: str
    outcome: str
    method: str
    file: str
    line: int
    raw: str

    def record(self):
        result = asdict(self)
        result['id'] = hashlib.sha256(f'{self.file}\0{self.line}\0{self.raw}'.encode()).hexdigest()[:24]
        result['timestamp'] = self.timestamp.isoformat(timespec='microseconds')
        return result


def finding(rule, severity, host, source, evidence, explanation, triggered_at=None):
    return dict(rule=rule, severity=severity, host=host, source_ip=source,
                triggered_at=triggered_at or evidence[-1].timestamp.isoformat(timespec='microseconds'),
                event_count=len(evidence), failure_count=sum(e.outcome == "failed" for e in evidence),
                accounts=sorted({item.user for item in evidence}), start=evidence[0].timestamp.isoformat(timespec='microseconds'),
                end=evidence[-1].timestamp.isoformat(timespec='microseconds'), explanation=explanation,
                evidence=[item.record() for item in evidence])

