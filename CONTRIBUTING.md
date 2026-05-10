# Contributing to Redlyne

Thanks for your interest in contributing. This document explains how to get a development environment running, the kinds of contributions we're looking for, and the process for submitting changes.

By participating in this project you agree to abide by the [Code of Conduct](CODE_OF_CONDUCT.md).

## Ways to Contribute

We welcome contributions of all sizes:

- **Bug reports** — open an [issue](https://github.com/redlyne-ai/redlyne/issues) with a clear repro
- **Feature requests** — open a [discussion](https://github.com/redlyne-ai/redlyne/discussions) first to align on direction
- **Detection rules** — submit new vulnerability patterns or improve existing ones
- **Documentation** — fix typos, clarify steps, add examples
- **Code** — bug fixes, performance improvements, new features

If you're not sure where to start, browse issues tagged [`good first issue`](https://github.com/redlyne-ai/redlyne/labels/good%20first%20issue).

## Development Setup

### Prerequisites

- **Windows 10/11** with [WSL2](https://learn.microsoft.com/windows/wsl/install) (Linux/macOS support is in progress)
- Inside WSL: Python 3.8+, `jq`, `bash`
- [Node.js](https://nodejs.org/) 18+ on the host
- [VS Code](https://code.visualstudio.com/) 1.89+
- [`@vscode/vsce`](https://github.com/microsoft/vscode-vsce) for packaging: `npm install -g @vscode/vsce`

### Get the code

```bash
git clone https://github.com/redlyne-ai/redlyne.git
cd redlyne
npm install
```

### Run from source

The fastest iteration loop is the **Extension Development Host**:

1. Open the cloned folder in VS Code
2. Press `F5`
3. A second VS Code window opens with the extension loaded
4. Edit code in the original window, press `Ctrl+R` in the dev window to reload

Console logs from the extension appear in the original VS Code's `Debug Console`.

### Build a `.vsix`

```bash
vsce package
```

This produces `redlyne-x.y.z.vsix` in the project root. Install it locally with:

```bash
code --install-extension redlyne-x.y.z.vsix
```

### Project structure

```
extension.js                # entry point, command registration, activation hooks
src/                        # JavaScript: command handlers, remediation flow
  RunPatchitpyFromText.js   #   wraps user selection, prepares the temp file
  execPatchitpy.js          #   spawns the Python engine and parses its JSON output
  Remediation.js            #   applies the fix to the buffer (atomic WorkspaceEdit)
  utilities/                #   small helpers
launch_tool/                # Python rule engine
  redlyne_engine.py         #   detection + remediation engine, single file
  rules/                    #   Devaic v2.0 schema rules + Redlyne extensions (459 rules)
tests/                      # parity tests + fixtures + bench harness
  bench_dataset.py          #   recall/precision benchmark on 3 datasets
  bench_patching.py         #   patch syntax + regression safety benchmark
benchmarks/                 # baseline snapshots (committed) + run results (gitignored)
scripts/preflight.sh        # local pre-vsce-package sanity check
images/icon.png             # marketplace icon
```

## Submitting Changes

1. **Open an issue first** for non-trivial changes so we can align before you spend time
2. **Fork** the repository and create a branch from `main` (e.g., `fix/wsl-path-spaces`, `feat/rule-jwt-none-alg`)
3. **Write code** with the existing style as a reference
4. **Test** locally before opening the PR — run `bash scripts/preflight.sh` (Python 3.10+ required, no other dependency)
5. **Open a Pull Request** with a clear title, a summary of the change, and a screenshot or short description of the user-visible behavior if applicable
6. Be ready to iterate on review feedback

### Commit messages

Use clear, present-tense commit messages. We don't enforce a strict format, but [Conventional Commits](https://www.conventionalcommits.org/) (`fix:`, `feat:`, `docs:`, `refactor:`, `perf:`) make changelog generation easier.

### Sign-off (DCO)

Each commit must be signed off using the [Developer Certificate of Origin](https://developercertificate.org/), confirming you have the right to contribute the code. Add `-s` to your commits:

```bash
git commit -s -m "feat: detect unsafe yaml.load"
```

This appends a `Signed-off-by:` line. By signing off you agree to the DCO.

## Submitting a New Detection Rule

Rules are the most welcome contribution category. A good rule submission includes:

- The vulnerability pattern (regex or AST shape) and where it appears in real-world AI-generated code
- A short example of vulnerable code
- The proposed remediation (replacement code)
- Edge cases that should NOT trigger the rule (false-positive guard)
- A reference to a CWE / CVE / OWASP entry where applicable

Open a [discussion](https://github.com/redlyne-ai/redlyne/discussions) first so we can decide on the rule format together — the rule schema is still evolving.

## License of Your Contributions

By contributing source code to Redlyne, you agree that your contributions will be licensed under the **Apache License 2.0** (the same license as the project). By contributing detection rules or datasets, you agree they will be licensed under **CC BY-NC-SA 4.0**, consistent with the rest of the bundled rule set.

See [LICENSE.md](LICENSE.md) for the full text.

## Getting Help

- **Bugs / feature requests**: [GitHub Issues](https://github.com/redlyne-ai/redlyne/issues)
- **Questions / ideas / showcase**: [GitHub Discussions](https://github.com/redlyne-ai/redlyne/discussions)
- **Commercial / partnership / press**: [redlyne.io](https://redlyne.io)
