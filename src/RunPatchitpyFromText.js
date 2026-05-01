const path = require('path');
const fs = require('fs');
const os = require('os');
const vscode = require('vscode');
const remediate = require('./Remediation');


const execPatchitpy = require('./execPatchitpy');
const delFile = require('./utilities/deleteFile');
const removePythonComments = require('./utilities/removePythonComments');


function runPatchitpyFromText() {
    return new Promise((resolve, reject) => {
        const editor = vscode.window.activeTextEditor;
        if (editor) {
            const document = editor.document;
            const selection = editor.selection; //get selected text from file
            let selectedText = document.getText(selection); //get selected text

            const filePath = document.uri.fsPath;
            const fileName = path.basename(filePath);

            // Use the OS temp directory for intermediate files instead of the user's
            // project folder. Prevents failures when the source file lives on a
            // mount that is not writable from inside WSL (e.g. shared drives,
            // /mnt/c/Mac/Home/... in Windows VMs that proxy a macOS host).
            const workDir = fs.mkdtempSync(path.join(os.tmpdir(), 'redlyne-'));
            const tempFilePath = path.join(workDir, 'codeFrom_' + fileName);

            // Check if the selected text is empty
            if (selectedText.trim() === '') {
                vscode.window.showErrorMessage('🔴 [Redlyne]: No code selected');
                return;
            }

            selectedText = "#PatchitPy ADD\n" + selectedText;
            selectedText = removePythonComments(selectedText);
            //console.log(selectedText);

            // Write text in temp-file
            fs.writeFile(tempFilePath, selectedText, (err) => {
                if (err) {
                    vscode.window.showErrorMessage(`Error writing to file: ${err.message}`);
                    return;
                }
            });

            execPatchitpy(tempFilePath)
            .then(() => {
                // Delete the temporary file after execution is complete
                delFile(tempFilePath);

                // remediate() uses this dir to read the bash script's results_*
                // folder, so it must match where the bash actually wrote them.
                remediate(workDir, fileName, editor, selection);

                //delete generated files after remediation

                resolve();
            })
            .catch((err) => {
                vscode.window.showErrorMessage(`🔴 [Redlyne]: Error executing the tool: ${err.message}`);
                reject(err); // Reject promise if there's an error
            });

        } else {
            reject(new Error('No active text editor'));
        }


    });
}


module.exports = runPatchitpyFromText;