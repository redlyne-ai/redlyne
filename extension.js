const vscode = require('vscode');
const fs = require('fs');
const path = require('path');
const { spawnSync } = require('child_process');
const runPatchitpyFromText = require('./src/RunPatchitpyFromText');


/**
 * Verify a usable Python interpreter is available. As of v0.1.0 the
 * engine is a single Python script — no WSL, no bash. We just need
 * `python3` (POSIX) or `python` / `py` (Windows).
 */
function checkPython() {
    const candidates = process.platform === 'win32'
        ? ['python', 'python3', 'py']
        : ['python3', 'python'];
    for (const cmd of candidates) {
        try {
            const res = spawnSync(cmd, ['--version'], { stdio: 'ignore' });
            if (res.status === 0) return true;
        } catch (_) { /* try next */ }
    }
    vscode.window.showErrorMessage(
        'Redlyne requires Python 3.10+ on PATH. Install Python and reload VS Code: ' +
        'https://www.python.org/downloads/'
    );
    return false;
}


function ensureScratchDirs(extensionPath) {
    // Engine output is fully in-memory + stdout, but we keep this dir
    // around for any future caching needs.
    const scratchDir = path.join(extensionPath, 'launch_tool', 'generated_file');
    try {
        fs.mkdirSync(scratchDir, { recursive: true });
    } catch (err) {
        console.warn('Redlyne: could not create scratch dir:', err.message);
    }
}


function activate(context) {
    console.log('Redlyne is now active!');
    ensureScratchDirs(context.extensionPath);

    let disposable1 = vscode.commands.registerCommand('redlyne.runAnalysis', () => {
        if (!checkPython()) return;
        runPatchitpyFromText();
    });
    context.subscriptions.push(disposable1);
}


function deactivate() {}


module.exports = { activate, deactivate };
