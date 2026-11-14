"""Public cross-platform checks; no private UI files are uploaded or executed."""
import hashlib
import json
import os
import pathlib
import platform
import subprocess
import tempfile

ROOT = pathlib.Path(__file__).resolve().parent.parent
RESULTS = ROOT / 'test-results'
RESULTS.mkdir(exist_ok=True)
summary = {'platform': platform.platform(), 'checks': []}


def step(name, args):
    result = subprocess.run(args, cwd=ROOT, capture_output=True, text=True, timeout=900)
    (RESULTS / (name + '.log')).write_text(result.stdout + result.stderr, encoding='utf-8')
    summary['checks'].append({'name': name, 'exit_code': result.returncode})
    if result.returncode:
        print(result.stdout + result.stderr)
        raise RuntimeError(name + ' failed')


try:
    tracked = subprocess.check_output(['git', 'ls-files'], cwd=ROOT, text=True).splitlines()
    assert not any(p.startswith('local-ui/') for p in tracked), 'Private UI must never be tracked'
    for name, args in [
        ('format', ['fmt', '--check']),
        ('clippy', ['clippy', '--locked', '--all-targets', '--', '-D', 'warnings']),
        ('tests', ['test', '--locked']),
        ('release', ['build', '--release', '--locked', '--bins']),
    ]:
        step(name, ['cargo', '+1.93.1', *args])
    binary = ROOT / 'target' / 'release' / ('iqaw.exe' if os.name == 'nt' else 'iqaw')
    def run(*args):
        return subprocess.check_output([str(binary), *map(str,args)], cwd=ROOT, stderr=subprocess.PIPE, timeout=30)
    assert run('--version').strip() == b'iqaw 4.2.0'
    with tempfile.TemporaryDirectory() as d:
        d = pathlib.Path(d)
        plain = d / 'plain.bin'
        plain.write_bytes(bytes(range(256)))
        for algorithm in ['aes128-gcm', 'aes256-gcm', 'chacha20-poly1305', 'xchacha20-poly1305']:
            key, envelope, recovered = (d / (algorithm + ext) for ext in ['.key', '.json', '.bin'])
            run('keygen', '--bits', '128' if algorithm == 'aes128-gcm' else '256', '--out', key)
            run('encrypt', '--algorithm', algorithm, '--input', plain, '--key-file', key, '--out', envelope)
            run('open', '--input', envelope, '--key-file', key, '--output-format', 'raw', '--out', recovered)
            assert recovered.read_bytes() == plain.read_bytes()
        assert run('hash', '--input', plain).strip().decode() == hashlib.sha256(plain.read_bytes()).hexdigest()
    summary['checks'].append({'name': 'release_roundtrips_and_hash', 'exit_code': 0})
    summary['passed'] = True
finally:
    (RESULTS / 'summary.json').write_text(json.dumps(summary, indent=2), encoding='utf-8')
