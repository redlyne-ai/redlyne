const fs = require('fs');

function deleteTempFile(tempFilePath) {
    fs.unlink(tempFilePath, (err) => {
        if (err) {
            console.error(`Error deleting file ${tempFilePath}: ${err.message}`);
            return;
        }
        //console.log(`File ${tempFilePath} deleted successfully`);
    });
}

module.exports = deleteTempFile;