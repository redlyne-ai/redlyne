const { spawn } = require('child_process');
const vscode = require('vscode');
const path = require('path');
const fs = require('fs');


/**
 * Find the Python interpreter to use. Tries `python3` first (POSIX
 * convention), then falls back to `python`. Returns the first one whose
 * --version succeeds, or null if neither is found.
 *
 * Cross-platform note: on macOS / Linux the binary is usually `python3`.
 * On Windows the official installer registers both `python` and the
 * `py` launcher; `python` is the more common shebang there.
 */
function findPython() {
    const { spawnSync } = require('child_process');
    const candidates = process.platform === 'win32'
        ? ['python', 'python3', 'py']
        : ['python3', 'python'];
    for (const cmd of candidates) {
        try {
            const res = spawnSync(cmd, ['--version'], { stdio: 'ignore' });
            if (res.status === 0) return cmd;
        } catch (_) { /* try next */ }
    }
    return null;
}


/**
 * Run the Redlyne Python engine on a single file and return the parsed
 * EngineResult JSON.
 *
 * The engine prints one JSON object to stdout when invoked with
 * `--format engine-result`. We capture stdout, parse it, and resolve
 * with the resulting object. Any non-zero exit or parse failure is
 * surfaced as a rejected promise so the caller can inform the user.
 */
function runEngine(srcFile) {
    return new Promise((resolve, reject) => {
        const python = findPython();
        if (!python) {
            const msg = 'Python 3 was not found on PATH. Install Python 3.10+ and reload VS Code.';
            vscode.window.showErrorMessage(`🔴 [Redlyne]: ${msg}`);
            return reject(new Error(msg));
        }

        const enginePath = path.join(__dirname, '..', 'launch_tool', 'redlyne_engine.py');
        if (!fs.existsSync(enginePath)) {
            const msg = `Engine not found at ${enginePath}. The extension install looks corrupted.`;
            vscode.window.showErrorMessage(`🔴 [Redlyne]: ${msg}`);
            return reject(new Error(msg));
        }

        vscode.window.showInformationMessage('🔴 [Redlyne]: Tool is running');

        const child = spawn(python, [enginePath, '--format', 'engine-result', srcFile]);
        let stdout = '';
        let stderr = '';
        child.stdout.on('data', (chunk) => { stdout += chunk.toString(); });
        child.stderr.on('data', (chunk) => { stderr += chunk.toString(); });
        child.on('error', (err) => {
            vscode.window.showErrorMessage(`🔴 [Redlyne]: Failed to start engine: ${err.message}`);
            reject(err);
        });
        child.on('close', (code) => {
            if (code !== 0) {
                vscode.window.showErrorMessage(`🔴 [Redlyne]: Engine exited with code ${code}: ${stderr}`);
                return reject(new Error(`engine exit ${code}: ${stderr}`));
            }
            let parsed;
            try {
                parsed = JSON.parse(stdout);
            } catch (e) {
                vscode.window.showErrorMessage(`🔴 [Redlyne]: Could not parse engine output: ${e.message}`);
                return reject(e);
            }
            vscode.window.showInformationMessage('🔴 [Redlyne]: Detection executed');
            resolve(parsed);
        });
    });
}


module.exports = runEngine;
