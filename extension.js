const vscode = require('vscode');
const fs = require('fs');
const path = require('path');
const { execSync } = require('child_process');
const runPatchitpyFromText = require('./src/RunPatchitpyFromText');

function ensureScriptsExecutable(extensionPath) {
    if (process.platform === 'win32') return;
    const scriptsDir = path.join(extensionPath, 'launch_tool');
    try {
        const files = fs.readdirSync(scriptsDir);
        files.filter(f => f.endsWith('.sh')).forEach(f => {
            try { fs.chmodSync(path.join(scriptsDir, f), 0o755); } catch (_) {}
        });
    } catch (err) {
        console.warn('Redlyne: could not chmod scripts:', err.message);
    }
}

function ensureScratchDirs(extensionPath) {
    // The bundled bash script writes intermediate files to launch_tool/generated_file/
    // without creating it first. The folder is empty in the repo and therefore not
    // shipped inside the .vsix, so we recreate it on activation.
    const scratchDir = path.join(extensionPath, 'launch_tool', 'generated_file');
    try {
        fs.mkdirSync(scratchDir, { recursive: true });
    } catch (err) {
        console.warn('Redlyne: could not create scratch dir:', err.message);
    }
}

function checkWindowsWSL() {
    if (process.platform !== 'win32') {
        vscode.window.showErrorMessage(
            'Redlyne currently runs only on Windows with WSL installed. ' +
            'Cross-platform support (Linux/macOS) is planned for a future release.'
        );
        return false;
    }
    try {
        execSync('wsl --status', { stdio: 'ignore' });
        return true;
    } catch (_) {
        vscode.window.showErrorMessage(
            'Redlyne requires WSL (Windows Subsystem for Linux). ' +
            'Please install WSL2 and try again: https://learn.microsoft.com/windows/wsl/install'
        );
        return false;
    }
}

function activate(context) {
    console.log('Redlyne is now active!');
    ensureScriptsExecutable(context.extensionPath);
    ensureScratchDirs(context.extensionPath);

    let disposable1 = vscode.commands.registerCommand('redlyne.runAnalysis', () => {
        if (!checkWindowsWSL()) return;
        runPatchitpyFromText();
    });
    context.subscriptions.push(disposable1);
}

function deactivate() {}

module.exports = { activate, deactivate };
