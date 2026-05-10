const vscode = require('vscode');
const replaceQuotes = require('./utilities/replaceQuotes');


/**
 * Decode the inline-encoded `remediated_code` field from the engine.
 *
 * The engine emits code with `\n ` as a literal separator (not real
 * newlines) for compatibility with the legacy bash output format. We
 * convert that back into multi-line text and trim a few quirks that
 * crept in during the bash era (leading newline, trailing space).
 */
function decodeInlineCode(s) {
    if (typeof s !== 'string' || !s) return '';
    let out = s.split('\\n ').join('\n').replace(/^\n/, '');
    if (out.endsWith(' ')) out = out.replace(/ +$/, '');
    return replaceQuotes(out);
}


/**
 * Compute which import lines to actually insert at the top of the file:
 * skip any import that is already present in the active document or
 * already part of the remediated snippet.
 *
 * The check matches the import statement *as a real Python statement*,
 * i.e. anchored at start-of-line (with optional leading whitespace) —
 * not as a bare substring. Otherwise comments like
 *     # expected: ast.literal_eval + import ast
 * would suppress the insertion of a real `import ast`.
 */
function escapeRegExp(s) {
    return s.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}

function alreadyImported(text, imp) {
    // Match `imp` only at the start of a line (modulo leading whitespace).
    // The `m` flag makes ^ match each line start, not just the doc start.
    const re = new RegExp('^[ \\t]*' + escapeRegExp(imp) + '(?:\\s|$)', 'm');
    return re.test(text);
}

function importsToPrepend(imports, remediatedCode, editor) {
    const text = editor.document.getText();
    let out = '';
    for (const imp of imports || []) {
        if (!imp) continue;
        if (alreadyImported(text, imp)) continue;
        if (alreadyImported(remediatedCode, imp)) continue;
        out += `${imp}\n`;
    }
    return out;
}


/**
 * Drive the user-facing remediation flow given the parsed EngineResult
 * dict produced by `runEngine` (src/execPatchitpy.js).
 *
 * Replaces the legacy bash workflow that wrote intermediate files into
 * a results_codeFrom_<name> directory — we now consume the JSON output
 * directly, which is faster and works on any OS that has Python.
 */
function remediate(result, editor, selection) {
    if (!result || result.status === 'safe') {
        vscode.window.showInformationMessage('🔴 [Redlyne]: No vulnerabilities found');
        return;
    }
    if (result.status === 'error') {
        vscode.window.showErrorMessage(`🔴 [Redlyne]: Engine error — ${result.error || 'unknown'}`);
        return;
    }

    const vulnList = (result.vulnerabilities || []).join(', ');
    if (vulnList) {
        vscode.window.showInformationMessage(`🔴 [Redlyne]: Detected vulnerabilities of ${vulnList}`);
    }

    const remediatedCode = decodeInlineCode(result.remediated_code);
    const originalCode = decodeInlineCode(result.original_code);

    // Print every comment the engine produced (one per matched rule).
    const comments = (result.comments || []).filter(Boolean);
    if (comments.length) {
        const bullet = comments.map(c => `• ${c}`).join('\n');
        vscode.window.showInformationMessage(`🔴 [Redlyne]:\n${bullet}`);
    }

    // Guard against legacy bash sentinel tokens leaking into the buffer.
    // The old engine emitted "NO-REM" / "REM-WITH-COMMENT" as the entire
    // remediated_code string when no real fix could be applied; if a
    // stale build of the engine ever resurfaces those, treat them as
    // "no real change" instead of writing the literal string into code.
    const LEGACY_SENTINELS = new Set(['NO-REM', 'REM-WITH-COMMENT', 'SAFE-CODE']);
    const trimmed = remediatedCode.trim();
    const isLegacySentinel = LEGACY_SENTINELS.has(trimmed);

    if (!remediatedCode || isLegacySentinel || remediatedCode === originalCode) {
        vscode.window.showInformationMessage('🔴 [Redlyne]: No automatic fix available — see comments above.');
        return;
    }

    const importsBlock = importsToPrepend(result.imports, remediatedCode, editor);

    vscode.window.showInformationMessage(
        '🔴 [Redlyne]: Do you want to fix the code?',
        'Yes',
        'No'
    ).then(choice => {
        if (choice !== 'Yes') {
            vscode.window.showInformationMessage('🔴 [Redlyne]: No change has been applied');
            return;
        }

        // We use a single atomic WorkspaceEdit instead of two chained
        // editor.edit(...) calls. With two edits the second one was
        // dropped silently in some VS Code versions — the buffer got
        // the snippet replaced but the imports never made it in.
        const wsEdit = new vscode.WorkspaceEdit();
        const uri = editor.document.uri;
        if (importsBlock !== '') {
            wsEdit.insert(uri, new vscode.Position(0, 0), importsBlock);
        }
        wsEdit.replace(uri, selection, remediatedCode);

        vscode.workspace.applyEdit(wsEdit).then(applied => {
            if (!applied) {
                vscode.window.showWarningMessage(
                    '🔴 [Redlyne]: VS Code refused to apply the edit.'
                );
                return;
            }
            const msg = importsBlock !== ''
                ? '🔴 [Redlyne]: Code modified — imports inserted at the top of the file'
                : '🔴 [Redlyne]: The code has been modified';
            vscode.window.showInformationMessage(msg);
        }, err => {
            vscode.window.showErrorMessage(`🔴 [Redlyne]: applyEdit error — ${err && err.message || err}`);
        });
    });
}


module.exports = remediate;
