// enprot VS Code extension.
//
// Provides:
//   - Commands: encrypt, decrypt, store, verify (call the enprot binary)
//   - Diagnostic: warn when a BEGIN WORD block contains plaintext
//
// The extension does NOT bundle the enprot binary. Users install
// enprot separately (cargo install, brew install, or Docker). The
// extension shells out via child_process.

const vscode = require("vscode");
const { execFile } = require("node:child_process");
const path = require("node:path");

/** @typedef {import('vscode').ExtensionContext} ExtensionContext */

/**
 * @param {ExtensionContext} ctx
 */
function activate(ctx) {
  const diag = vscode.languages.createDiagnosticCollection("enprot");

  // Refresh diagnostics whenever an editable document changes.
  ctx.subscriptions.push(
    vscode.workspace.onDidChangeTextDocument((e) => updateDiagnostics(diag, e.document)),
    vscode.workspace.onDidOpenTextDocument((doc) => updateDiagnostics(diag, doc)),
  );

  // Initial pass for already-open documents.
  for (const doc of vscode.workspace.textDocuments) {
    updateDiagnostics(diag, doc);
  }

  ctx.subscriptions.push(
    vscode.commands.registerCommand("enprot.encryptFile", (uri) => runEnprot("encrypt", uri)),
    vscode.commands.registerCommand("enprot.decryptFile", (uri) => runEnprot("decrypt", uri)),
    vscode.commands.registerCommand("enprot.storeFile",   (uri) => runEnprot("store",   uri)),
    vscode.commands.registerCommand("enprot.verifyFile",  (uri) => runEnprot("verify",  uri)),
  );
}

exports.activate = activate;

function deactivate() {}

/**
 * Run enprot against a document. If `uri` is undefined (e.g. command
 * palette invocation), fall back to the active editor's document.
 */
function runEnprot(operation, uri) {
  const target = uri
    ? uri
    : vscode.window.activeTextEditor && vscode.window.activeTextEditor.document.uri;

  if (!target) {
    vscode.window.showWarningMessage(`enprot: no file to ${operation}.`);
    return;
  }

  const cfg = vscode.workspace.getConfiguration("enprot");
  const bin = cfg.get("binaryPath", "enprot");
  const casdir = cfg.get("defaultCasdir", ".cas");

  const args = [operation, "-c", casdir, target.fsPath];

  // Prompt for the WORD=password pair interactively so passwords
  // never land in the editor's command history.
  vscode.window.showInputBox({
    prompt: `WORD=password for ${operation} (e.g. SECRET=hunter2). Leave empty to skip.`,
    password: false,
    ignoreFocusOut: true,
  }).then((input) => {
    if (input === undefined) return;
    if (input.trim()) {
      args.splice(2, 0, "-w", input.trim());
    }
    execFile(bin, args, { cwd: path.dirname(target.fsPath) }, (err, _stdout, stderr) => {
      if (err) {
        vscode.window.showErrorMessage(`enprot ${operation} failed: ${stderr || err.message}`);
        return;
      }
      vscode.window.showInformationMessage(`enprot ${operation} OK`);
    });
  });
}

/**
 * @param {vscode.DiagnosticCollection} collection
 * @param {vscode.TextDocument} doc
 */
function updateDiagnostics(collection, doc) {
  const cfg = vscode.workspace.getConfiguration("enprot");
  if (!cfg.get("warnOnPlaintextBeginBlock", true)) {
    collection.delete(doc.uri);
    return;
  }

  const diags = [];
  let inBegin = null;          // { word, startLine, bodyClean }
  let bodyClean = false;

  for (let i = 0; i < doc.lineCount; i++) {
    const line = doc.lineAt(i).text;
    const m = line.match(/^\s*[#/]{1,2}\s*<?\(?\s*(BEGIN|END|ENCRYPTED|STORED|DATA)\b(?:\s+(\w+))?/);
    if (m) {
      const kw = m[1];
      const word = m[2] || "";
      if (kw === "BEGIN") {
        inBegin = { word, startLine: i, bodyClean: false };
        bodyClean = false;
      } else if (kw === "ENCRYPTED" || kw === "STORED" || kw === "DATA") {
        bodyClean = true;
        if (inBegin) inBegin.bodyClean = true;
      } else if (kw === "END") {
        if (inBegin && !inBegin.bodyClean) {
          const range = new vscode.Range(inBegin.startLine, 0, i, line.length);
          diags.push(new vscode.Diagnostic(
            range,
            `enprot: plaintext inside BEGIN ${inBegin.word} block. Run enprot encrypt or enprot store before commit.`,
            vscode.DiagnosticSeverity.Warning,
          ));
        }
        inBegin = null;
        bodyClean = false;
      }
    } else if (inBegin && line.trim() !== "" && !bodyClean) {
      // Non-empty line that isn't a directive => plaintext body.
      // Don't flag yet; flag at the matching END.
    }
  }

  if (diags.length) {
    collection.set(doc.uri, diags);
  } else {
    collection.delete(doc.uri);
  }
}

module.exports = { activate, deactivate };
