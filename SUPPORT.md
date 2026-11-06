# Support policy

Supported scope: offline Linux/OpenSSH exported log analysis on Python 3.10–3.14. Windows, macOS, journal JSON and live monitoring are not currently supported deployment targets.

Use the latest published release for fixes. Earlier 0.x releases do not have a separate maintenance branch. There is no guaranteed response time. Patch releases aim to preserve CLI behavior; correctness or safety fixes can change findings. Report schemas are explicitly versioned; consumers must inspect schema_version and tolerate additional fields.

File reproducible bugs through the issue template. Include the tool version, Python version, operating system, command with sensitive paths removed, and a small synthetic example. Do not post authentication logs containing personal or operational information.

Before operational use, verify parser coverage, thresholds, exclusions, known benign and attack scenarios, runtime and memory on a representative read-only export. Run alongside existing investigations until results are understood. False positives and missed detections are possible.
