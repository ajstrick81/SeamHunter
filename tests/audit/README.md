# Audit scripts

Heavier than the unit tests. Run from the app folder:

    python tests/audit/fuzz.py . 1500     # every parser, N mutants each
    python tests/audit/e2e.py . 300       # whole scans of corrupted APKs
    python tests/audit/apkm.py . 150      # whole scans of .apkm bundles with a corrupted split

fuzz.py uses SIGALRM for hang detection (Linux/macOS); on Windows run e2e.py.
