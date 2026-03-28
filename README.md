# semgrep-lite
Simple pattern-based source code scanner. Finds hardcoded passwords, TODOs, eval(), SQL injection, bare excepts, and more. Zero dependencies.
## Usage
```
python3 semgrep_lite.py ./src
python3 semgrep_lite.py . --rules hardcoded-password,eval-usage --ext .py
python3 semgrep_lite.py . --json
```
