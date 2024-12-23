import * as vscode from "vscode";
import * as CryptoJS from "crypto-js";
import { hashText } from "./utils";

export function activate(context: vscode.ExtensionContext) {
    console.log("Inline Cryptography Toolkit is now active.");

    // Encrypt Command
    const encryptCommand = vscode.commands.registerCommand("inlineCrypto.encrypt", async () => {
        const editor = vscode.window.activeTextEditor;
        if (!editor) {
            vscode.window.showErrorMessage("No active editor found.");
            return;
        }

        const selectedText = editor.document.getText(editor.selection);
        if (!selectedText) {
            vscode.window.showErrorMessage("Please select some text to encrypt.");
            return;
        }

        const algorithms = ["AES", "TripleDES", "Base64"];
        const algorithm = await vscode.window.showQuickPick(algorithms, {
            title: "Select Encryption Algorithm",
            canPickMany: false,
        });

        if (!algorithm) {
            vscode.window.showErrorMessage("No encryption algorithm selected.");
            return;
        }

        const key =
            vscode.workspace.getConfiguration("inlineCrypto").get<string>("defaultKey") || "your-secret-key";

        let encryptedText: string;
        try {
            switch (algorithm) {
                case "AES":
                    encryptedText = CryptoJS.AES.encrypt(selectedText, key).toString();
                    break;
                case "TripleDES":
                    encryptedText = CryptoJS.TripleDES.encrypt(selectedText, key).toString();
                    break;
                case "Base64":
                    encryptedText = CryptoJS.enc.Base64.stringify(CryptoJS.enc.Utf8.parse(selectedText));
                    break;
                default:
                    throw new Error("Unsupported encryption algorithm.");
            }

            editor.edit((editBuilder) => {
                editBuilder.replace(editor.selection, encryptedText);
            });

            vscode.window.showInformationMessage(`Text encrypted successfully using ${algorithm}.`);
        } catch (error) {
            const errorMessage = (error as Error).message;
            vscode.window.showErrorMessage(`Encryption failed: ${errorMessage}`);
        }
    });

    // Decrypt Command
    const decryptCommand = vscode.commands.registerCommand("inlineCrypto.decrypt", async () => {
        const editor = vscode.window.activeTextEditor;
        if (!editor) {
            vscode.window.showErrorMessage("No active editor found.");
            return;
        }

        const selectedText = editor.document.getText(editor.selection);
        if (!selectedText) {
            vscode.window.showErrorMessage("Please select some text to decrypt.");
            return;
        }

        const algorithms = ["AES", "TripleDES", "Base64"];
        const algorithm = await vscode.window.showQuickPick(algorithms, {
            title: "Select Decryption Algorithm",
            canPickMany: false,
        });

        if (!algorithm) {
            vscode.window.showErrorMessage("No decryption algorithm selected.");
            return;
        }

        const key =
            vscode.workspace.getConfiguration("inlineCrypto").get<string>("defaultKey") || "your-secret-key";

        let decryptedText: string;
        try {
            switch (algorithm) {
                case "AES":
                    decryptedText = CryptoJS.AES.decrypt(selectedText, key).toString(CryptoJS.enc.Utf8);
                    break;
                case "TripleDES":
                    decryptedText = CryptoJS.TripleDES.decrypt(selectedText, key).toString(CryptoJS.enc.Utf8);
                    break;
                case "Base64":
                    decryptedText = CryptoJS.enc.Base64.parse(selectedText).toString(CryptoJS.enc.Utf8);
                    break;
                default:
                    throw new Error("Unsupported decryption algorithm.");
            }

            if (!decryptedText) {
                throw new Error("Decryption failed.");
            }

            editor.edit((editBuilder) => {
                editBuilder.replace(editor.selection, decryptedText);
            });

            vscode.window.showInformationMessage(`Text decrypted successfully using ${algorithm}.`);
        } catch (error) {
            const errorMessage = (error as Error).message;
            vscode.window.showErrorMessage(`Decryption failed: ${errorMessage}`);
        }
    });

    // Generate Hash Command
    const hashCommand = vscode.commands.registerCommand("inlineCrypto.hash", async () => {
        const editor = vscode.window.activeTextEditor;
        if (!editor) {
            vscode.window.showErrorMessage("No active editor found.");
            return;
        }

        const selectedText = editor.document.getText(editor.selection);
        if (!selectedText) {
            vscode.window.showErrorMessage("Please select some text to hash.");
            return;
        }

        const algorithms = ["MD5", "SHA256", "SHA512"];
        const algorithm = await vscode.window.showQuickPick(algorithms, {
            title: "Select Hash Algorithm",
            canPickMany: false,
        });

        if (!algorithm) {
            vscode.window.showErrorMessage("No hash algorithm selected.");
            return;
        }

        // Cast the selected algorithm to the type "MD5" | "SHA256" | "SHA512"
        const algorithmType = algorithm as "MD5" | "SHA256" | "SHA512";

        const hashedText = hashText(selectedText, algorithmType);

        editor.edit((editBuilder) => {
            editBuilder.replace(editor.selection, hashedText);
        });

        vscode.window.showInformationMessage(`Text hashed successfully using ${algorithm}.`);
    });

    context.subscriptions.push(encryptCommand, decryptCommand, hashCommand);
}

export function deactivate() {
    console.log("Inline Cryptography Toolkit is now deactivated.");
}
