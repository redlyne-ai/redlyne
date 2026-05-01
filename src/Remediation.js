const fs = require('fs');
const path = require('path');
const vscode = require('vscode');
const deleteDirectory = require('./utilities/deleteDirectory');
const replaceQuotes = require('./utilities/replaceQuotes'); 

function getRemediation(remediationFilePath) {

    const fileData = fs.readFileSync(remediationFilePath, 'utf8');
    const lines = fileData.split('\n');
    const vuln = lines[0];
    let remediatedCode ="";
    let comments = [];
    let imports = [];

    if(lines[1] === 'NO-REM'){
        remediatedCode = 'NO-REM';
    }else if(lines[1] === 'REM-WITH-COMMENT'){
        remediatedCode = 'REM-WITH-COMMENT';
    }else if(lines[2]){
        //remediatedCode = lines[2].split('\\n ').join('\n');
        remediatedCode = lines[2].split('\\n ').join('\n').replace(/^\n/, '');
        if (remediatedCode.endsWith(' ')) {
            remediatedCode = remediatedCode.replace(/ +$/, '');
        }
        remediatedCode = replaceQuotes(remediatedCode);
    }

    let i=3;
    while(lines[i] !== 'imports' && i < lines.length){
        comments.push(lines[i]);
        i++;
    }
    i++;
    for (i; i < lines.length; i++) {
        imports.push(lines[i]);
    }
    
    return {
        vuln: vuln,
        remediatedCode: remediatedCode,
        comments: comments,
        imports: imports
    };
}

function checkImports(imports, remediateCode, editor) {
    const document = editor.document;
    const text = document.getText();

    //console.log(text);
    let importsToImport = "";
    for (let i = 0; i < imports.length; i++) {
        if(imports[i] !== '' && !text.includes(imports[i]) && !remediateCode.includes(imports[i])){
            importsToImport += `${imports[i]}\n`;
        }
    }

    return importsToImport;
   
}

function remediate(fileDir, fileName, editor, selection) {
    const remediationPath = path.join(fileDir, `results_codeFrom_${path.parse(fileName).name}\\`);

    // Leggi il primo file nella directory remediationPath
    const files = fs.readdirSync(remediationPath).filter(file => {
        const filePath = path.join(remediationPath, file);
        return fs.statSync(filePath).isFile();
    });

    if (files.length === 0) {
        console.error('No files found in the remediation directory.');
        return;
    }

    deleteDirectory(remediationPath);

    const remediatedFile = files[0];
    const remediatedFilePathFilePath = path.join(remediationPath, remediatedFile);
    //console.log(remediatedFilePathFilePath); 


    const result = getRemediation(remediatedFilePathFilePath);
    
    if (result.vuln === 'SAFE-CODE') {
        vscode.window.showInformationMessage('🔴 [Redlyne]: No vulnerabilities found');
        return;
    }
    let vuln = result.vuln.trim().replace(/^, /, '');
    vscode.window.showInformationMessage(`🔴 [Redlyne]: Detected vulnerabilities of ${vuln}`);
    const remediatedCode = result.remediatedCode;

    if(remediatedCode === 'NO-REM'){
        vscode.window.showInformationMessage('🔴 [Redlyne]: No remediation available');
        return;
    }

    let commentToPrint = "";
    for (let i = 0; i < result.comments.length; i++) {
        if(result.comments[i] !== ''){
            commentToPrint += `• ${result.comments[i]}\n`;
        }
    }

    vscode.window.showInformationMessage(`🔴 [Redlyne]:\n${commentToPrint}`);
    if(result.remediatedCode === 'REM-WITH-COMMENT'){ 
        return;
    }
    
    const importsToImport = checkImports(result.imports, result.remediatedCode,editor);

    
    vscode.window.showInformationMessage(
        `🔴 [Redlyne]: Do you want to fix the code?`, 
        'Yes', 
        'No'
    ).then(choice => {
        if (choice === 'Yes') {
            // Rimpiazza il codice se l'utente accetta
            editor.edit(editBuilder => {
                editBuilder.replace(selection, remediatedCode);
                if(importsToImport !== ""){
                    editBuilder.insert(new vscode.Position(0, 0), importsToImport);
                }
            });
            vscode.window.showInformationMessage('🔴 [Redlyne]: The code has been modified');
        } else {
            // Notifica l'utente che ha rifiutato
            vscode.window.showInformationMessage('🔴 [Redlyne]: No change has been applied');
        }
    });
}






module.exports = remediate;