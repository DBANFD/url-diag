"""Package only the application and explicitly approved public documents."""
import argparse
import hashlib
import pathlib
import re
import tarfile
import zipfile

DOCS = ['README.md', 'SOURCES.md', 'REPORT_SCHEMA.md', 'TESTING.md', 'CHANGELOG.md', 'NOTICE.md', 'LICENSE']
TARGETS = ['x86_64-pc-windows-msvc', 'aarch64-pc-windows-msvc',
           'x86_64-unknown-linux-gnu', 'x86_64-unknown-linux-musl',
           'x86_64-apple-darwin', 'aarch64-apple-darwin']

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--target', choices=TARGETS, required=True)
    parser.add_argument('--tag', required=True)
    args = parser.parse_args()
    version = re.search(r'^version = "([^"]+)"', pathlib.Path('Cargo.toml').read_text(), re.M)[1]
    if args.tag != 'v' + version:
        raise SystemExit('Release tag must match Cargo package version')
    windows = 'windows' in args.target
    binary = 'url-diag.exe' if windows else 'url-diag'
    source = pathlib.Path('target') / args.target / 'release' / binary
    if not source.is_file():
        raise SystemExit('Built binary missing: ' + str(source))
    stem = f'url-diag-{args.tag}-{args.target}'
    out = pathlib.Path('dist')
    out.mkdir(exist_ok=True)
    archive = out / (stem + ('.zip' if windows else '.tar.gz'))
    files = [(source, binary)] + [(pathlib.Path(p), p) for p in DOCS]
    if windows:
        with zipfile.ZipFile(archive, 'x', zipfile.ZIP_DEFLATED) as z:
            for path, name in files:
                z.write(path, stem + '/' + name)
        with zipfile.ZipFile(archive) as z:
            assert set(z.namelist()) == {stem + '/' + name for _, name in files}
    else:
        with tarfile.open(archive, 'x:gz') as z:
            for path, name in files:
                info = z.gettarinfo(str(path), stem + '/' + name)
                info.uid = info.gid = 0
                info.uname = info.gname = ''
                info.mode = 0o755 if name == binary else 0o644
                with path.open('rb') as f:
                    z.addfile(info, f)
        with tarfile.open(archive) as z:
            assert set(z.getnames()) == {stem + '/' + name for _, name in files}
    digest = hashlib.sha256(archive.read_bytes()).hexdigest()
    archive.with_name(archive.name + '.sha256').write_text(digest + '  ' + archive.name + '\n', encoding='utf-8', newline='\n')
    print(archive)

if __name__ == '__main__':
    main()
