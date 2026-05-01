const { exec } = require('child_process');
const vscode = require('vscode');
const path = require('path');
const convertWindowsToUnixPath = require('./utilities/convertPathWindowsToUnix');


function eseguiScriptBash(srcFile) {
    return new Promise((resolve, reject) => {
        const tool_path = convertWindowsToUnixPath(path.join(__dirname,`../launch_tool`));
        const tool_starter = convertWindowsToUnixPath(path.join(__dirname,`../launch_tool/patchitpy_starter.sh`));
        const convertedSrcFile = convertWindowsToUnixPath(srcFile);
        // Comando per eseguire lo script Bash usando WSL
        const comando = "wsl " + tool_starter + " " + convertedSrcFile + " " + tool_path;
        //console.log(comando);
        vscode.window.showInformationMessage("🔴 [Redlyne]: Tool is running");
        
        // Esegui il comando
        exec(comando, (error, stdout, stderr) => {
            if (error) {
                vscode.window.showErrorMessage(`🔴 [Redlyne]: Error during execution of the script: ${error}`);
                reject(error);
                return;
            }
            if (stderr) {
                vscode.window.showErrorMessage(`🔴 [Redlyne]: Error in the script: ${stderr}`);
                reject(stderr);
                return;
            }
            //console.log(stdout);
            vscode.window.showInformationMessage("🔴 [Redlyne]: Detection executed");

            // Filtra il valore della variabile runtime
            const match = stdout.match(/runtime=(.*)/);            
            if (match) {                 
                vscode.window.showInformationMessage("🔴 [Redlyne]: Runtime: " + parseFloat(match[1].trim()).toFixed(3) + " seconds");      
            }
            else {                 
                vscode.window.showWarningMessage("🔴 [Redlyne]: Errore definizione runtime");
            }

            resolve();

        });
        
    });
}


module.exports = eseguiScriptBash;