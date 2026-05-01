function convertWindowsToUnixPath(windowsPath) {
  // Verifica se il percorso inizia con una lettera di unità
  if (/^[A-Za-z]:\\/.test(windowsPath)) {
    // Sostituisci la lettera di unità con "/mnt/c" (o "/mnt/d", "/mnt/e", ecc. a seconda della lettera di unità)
    let unixPath = '/mnt/' + windowsPath.charAt(0).toLowerCase() + windowsPath.slice(2).replace(/\\/g, '/');
    
    // Sostituisci gli spazi con "\ "
    unixPath = unixPath.replace(/ /g, '\\ ');

    return unixPath;
  } else {
    // Se il percorso non inizia con una lettera di unità, restituisci semplicemente il percorso senza modifiche
    return windowsPath;
  }
}

module.exports = convertWindowsToUnixPath;
