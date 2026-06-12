import * as path from "node:path";
import * as vscode from "vscode";
import { KeyOptions } from "./dotseal/keys";
import {
  DOTSEAL_SCHEME,
  DotsealFsProvider,
  fileSystemError,
  toDotsealUri
} from "./provider";

export function activate(context: vscode.ExtensionContext): void {
  const provider = new DotsealFsProvider(readKeyOptions);

  context.subscriptions.push(
    vscode.workspace.registerFileSystemProvider(DOTSEAL_SCHEME, provider, {
      isCaseSensitive: process.platform !== "win32"
    }),
    vscode.commands.registerCommand("dotseal.openEncrypted", openEncrypted),
    vscode.workspace.onDidOpenTextDocument((document) => {
      void maybeRedirectEncryptedDocument(document);
    }),
    vscode.window.onDidChangeActiveTextEditor((editor) => {
      if (editor !== undefined) {
        void maybeRedirectEncryptedDocument(editor.document);
      }
    })
  );
}

export function deactivate(): void {
  // Nothing to clean up; subscriptions are disposed by VS Code.
}

async function openEncrypted(uri?: vscode.Uri): Promise<boolean> {
  const target = uri ?? (await pickEncryptedFile());
  if (target === undefined) {
    return false;
  }

  if (!isEncryptedEnvFile(target)) {
    await vscode.window.showWarningMessage("Dotseal only opens files named .env.enc.");
    return false;
  }

  try {
    const editor = await vscode.window.showTextDocument(toDotsealUri(target), {
      preview: false
    });
    await setEnvLanguage(editor.document);
    return true;
  } catch (error) {
    const fsError = fileSystemError(error);
    await vscode.window.showErrorMessage(`dotseal: ${fsError.message}`);
    return false;
  }
}

async function maybeRedirectEncryptedDocument(document: vscode.TextDocument): Promise<void> {
  if (document.uri.scheme !== "file" || !isEncryptedEnvFile(document.uri)) {
    return;
  }

  const autoOpen = vscode.workspace
    .getConfiguration("dotseal", document.uri)
    .get<boolean>("autoOpen", true);
  if (!autoOpen) {
    return;
  }

  if (await openEncrypted(document.uri)) {
    await closeTabForUri(document.uri);
  }
}

async function closeTabForUri(uri: vscode.Uri): Promise<void> {
  for (const group of vscode.window.tabGroups.all) {
    const tab = group.tabs.find((candidate) => tabMatchesUri(candidate, uri));
    if (tab !== undefined) {
      await vscode.window.tabGroups.close(tab);
      return;
    }
  }
}

function tabMatchesUri(tab: vscode.Tab, uri: vscode.Uri): boolean {
  const input = tab.input;
  if (input instanceof vscode.TabInputText) {
    return input.uri.toString() === uri.toString();
  }
  if (input instanceof vscode.TabInputTextDiff) {
    return input.original.toString() === uri.toString() || input.modified.toString() === uri.toString();
  }
  return false;
}

async function pickEncryptedFile(): Promise<vscode.Uri | undefined> {
  const active = vscode.window.activeTextEditor?.document.uri;
  if (active !== undefined && isEncryptedEnvFile(active)) {
    return active;
  }

  const [selection] =
    (await vscode.window.showOpenDialog({
      canSelectFiles: true,
      canSelectFolders: false,
      canSelectMany: false,
      filters: {
        "dotseal encrypted env": ["enc"]
      },
      title: "Open .env.enc with dotseal"
    })) ?? [];
  return selection;
}

function isEncryptedEnvFile(uri: vscode.Uri): boolean {
  return uri.scheme === "file" && path.basename(uri.fsPath) === ".env.enc";
}

let warnedAboutWorkspaceMasterKey = false;

function readKeyOptions(): KeyOptions {
  const config = vscode.workspace.getConfiguration("dotseal");
  // Workspace settings are routinely committed to git, so a masterKey set
  // there is one `git push` away from leaking. Only honor the user-level
  // (global) value and warn when a workspace value is being ignored.
  const inspected = config.inspect<string>("masterKey");
  const workspaceValue =
    inspected?.workspaceValue ?? inspected?.workspaceFolderValue;
  if (workspaceValue?.trim() && !warnedAboutWorkspaceMasterKey) {
    warnedAboutWorkspaceMasterKey = true;
    void vscode.window.showWarningMessage(
      "dotseal: ignoring dotseal.masterKey from workspace settings — workspace " +
        "settings are typically committed to git. Set it in your user settings, " +
        "or better, use DOTSEAL_MASTER_KEY / a .dotseal.key file."
    );
  }
  return {
    masterKey: inspected?.globalValue ?? "",
    keyFile: config.get<string>("keyFile", "")
  };
}

async function setEnvLanguage(document: vscode.TextDocument): Promise<void> {
  try {
    await vscode.languages.setTextDocumentLanguage(document, "dotenv");
  } catch {
    try {
      await vscode.languages.setTextDocumentLanguage(document, "properties");
    } catch {
      // Keep the virtual editor usable even when no dotenv/properties language is available.
    }
  }
}
