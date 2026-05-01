const fs = require('fs');
const path = require('path');
const vscode = require('vscode');
const execPatchitpy = require('./execPatchitpy');

function runPatchitpyFromFile(uri) {
    return new Promise((resolve, reject) => {
        const filePath = uri.fsPath;

        // Verifica il tipo di percorso
        fs.stat(filePath, (err, stats) => {
            if (err) {
                reject(err); // Gestisci errori di lettura del file system
                return;
            }

            if (stats.isFile()) {
                // Esegui solo se è un file
                execPatchitpy(filePath)
                    .then(() => {
                        console.log("PatchitPy Executed");
                        resolve();
                    })
                    .catch((err) => {
                        reject(err);
                    });
            } else {
                vscode.window.showErrorMessage(`Error executing tool: the path ${filePath} is not a file`);
                reject(new Error(`Il percorso ${filePath} non è un file.`));
            }
        });
    });
}

module.exports = runPatchitpyFromFile;
