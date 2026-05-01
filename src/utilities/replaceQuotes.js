function replaceQuotes(code) {
    // Remove quotes
    code = code.replace(/\\"/g, "''");;


    return code;
}


module.exports = replaceQuotes;