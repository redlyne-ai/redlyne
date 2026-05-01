const fs = require('fs');
const path = require('path');

/**
 * Elimina una directory e tutto il suo contenuto.
 * 
 * @param {string} dirPath - Il percorso della directory da eliminare.
 */
function deleteDirectory(dirPath) {
    fs.rm(dirPath, { recursive: true, force: true }, (err) => {
        if (err) {
            console.error(`Errore durante l'eliminazione della directory: ${err.message}`);
        } 
        /*
        else {
            console.log('Directory eliminata con successo');
        }
        */
    });
}


module.exports = deleteDirectory;