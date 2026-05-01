function removePythonComments(code) {
    
    // Remove multiline comments
    code = code.replace(/(?<![=(\s]\s*)'''[\s\S]*?'''/g, '');
    code = code.replace(/(?<![=(\s]\s*)"""[\s\S]*?"""/g, '');
    code = code.replace(/(?<=^\s{4,})'''[\s\S]*?'''/gm, '');

    
    // Remove single-line comments
    code = code.replace(/#.*$/gm, '');
    
    return code;
}


module.exports = removePythonComments;