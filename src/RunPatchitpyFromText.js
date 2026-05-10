const path = require('path');
const fs = require('fs');
const os = require('os');
const vscode = require('vscode');

const remediate = require('./Remediation');
const runEngine = require('./execPatchitpy');
const delFile = require('./utilities/deleteFile');


/**
 * Run the Redlyne engine on the user's current text selection.
 *
 * Flow:
 *   1. Capture selected text from the active editor.
 *   2. Write it to a temp file under the OS temp dir (avoids issues
 *      with read-only mounts and shared-folder permissions).
 *   3. Invoke the Python engine, which returns a parsed EngineResult
 *      JSON object.
 *   4. Hand the dict to remediate() which drives the user prompts.
 *   5. Clean up the temp file regardless of outcome.
 */
function runPatchitpyFromText() {
    return new Promise((resolve, reject) => {
        const editor = vscode.window.activeTextEditor;
        if (!editor) {
            return reject(new Error('No active text editor'));
        }

        const document = editor.document;
        const selection = editor.selection;
        let selectedText = document.getText(selection);

        if (selectedText.trim() === '') {
            vscode.window.showErrorMessage('🔴 [Redlyne]: No code selected');
            return resolve();
        }

        const fileName = path.basename(document.uri.fsPath);
        const workDir = fs.mkdtempSync(path.join(os.tmpdir(), 'redlyne-'));
        const tempFilePath = path.join(workDir, 'codeFrom_' + fileName);

        // We send the selected text to the engine VERBATIM. Two legacy
        // pieces have been removed:
        //   - The `#PatchitPy ADD\n` marker prefix, which was only needed
        //     by the bash pipeline.
        //   - `removePythonComments(...)`, which stripped every `#` and
        //     triple-quoted string before scanning. That made docstrings
        //     and explanatory comments disappear from the patched code
        //     the user got back. The Python engine handles comments
        //     correctly without preprocessing.
        //
        // Always write UTF-8: VS Code gives us text as a JS string
        // (UTF-16 internally) and the Python engine reads with
        // encoding="utf-8". Explicit for cross-platform consistency.
        fs.writeFileSync(tempFilePath, selectedText, { encoding: 'utf8' });

        runEngine(tempFilePath)
            .then((result) => {
                remediate(result, editor, selection);
                resolve();
            })
            .catch((err) => {
                vscode.window.showErrorMessage(`🔴 [Redlyne]: Error executing the tool: ${err.message}`);
                reject(err);
            })
            .finally(() => {
                // Best-effort cleanup; ignore failures (next reboot will
                // reclaim the OS temp dir anyway).
                try { delFile(tempFilePath); } catch (_) {}
                try { fs.rmdirSync(workDir); } catch (_) {}
            });
    });
}


module.exports = runPatchitpyFromText;
