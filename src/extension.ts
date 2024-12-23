import * as vscode from 'vscode';
import * as CryptoJS from 'crypto-js';
import * as forge from 'node-forge';  // For RSA encryption and decryption

export function activate(context: vscode.ExtensionContext) {
    console.log("Inline Cryptography Toolkit is now active.");

    // Encrypt Command
    const encryptCommand = vscode.commands.registerCommand('inlineCrypto.encrypt', async () => {
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

        const key = await promptForKey("Enter the encryption key:");
        if (!key) {
            vscode.window.showErrorMessage("Encryption key is required.");
            return;
        }

        const algorithm = await promptForAlgorithm("Choose an encryption algorithm", [
            { label: "AES", value: "AES" },
            { label: "TripleDES", value: "TripleDES" },
            { label: "RC4", value: "RC4" },
            { label: "RSA", value: "RSA" },  // Adding RSA
            { label: "Blowfish", value: "Blowfish" },
            { label: "Twofish", value: "Twofish" }
        ]);

        const encryptedText = encryptText(selectedText, key, algorithm);
        editor.edit((editBuilder) => {
            editBuilder.replace(editor.selection, encryptedText);
        });

        vscode.window.showInformationMessage("Text encrypted successfully.");
    });

    // Decrypt Command
    const decryptCommand = vscode.commands.registerCommand('inlineCrypto.decrypt', async () => {
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

        const key = await promptForKey("Enter the decryption key:");
        if (!key) {
            vscode.window.showErrorMessage("Decryption key is required.");
            return;
        }

        const algorithm = await promptForAlgorithm("Choose a decryption algorithm", [
            { label: "AES", value: "AES" },
            { label: "TripleDES", value: "TripleDES" },
            { label: "RC4", value: "RC4" },
            { label: "RSA", value: "RSA" }
        ]);

        const decryptedText = decryptText(selectedText, key, algorithm);
        editor.edit((editBuilder) => {
            editBuilder.replace(editor.selection, decryptedText);
        });

        vscode.window.showInformationMessage("Text decrypted successfully.");
    });

    // Hash Command
    const hashCommand = vscode.commands.registerCommand('inlineCrypto.hash', async () => {
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

        const algorithm = await promptForAlgorithm("Choose a hash algorithm", [
            { label: "SHA-256", value: "SHA256" },
            { label: "SHA-512", value: "SHA512" },
            { label: "MD5", value: "MD5" },
            { label: "HMAC", value: "HMAC" }
        ]);

        const hashedText = hashText(selectedText, algorithm);
        editor.edit((editBuilder) => {
            editBuilder.replace(editor.selection, hashedText);
        });

        vscode.window.showInformationMessage("Text hashed successfully.");
    });

    context.subscriptions.push(encryptCommand, decryptCommand, hashCommand);
}

// Helper functions

// Prompt the user to input a key (for encryption/decryption)
async function promptForKey(prompt: string): Promise<string | undefined> {
    const key = await vscode.window.showInputBox({
        placeHolder: prompt,
        password: true
    });
    return key;
}

// Prompt the user to choose an algorithm
async function promptForAlgorithm(prompt: string, options: { label: string; value: string }[]): Promise<string> {
    const selection = await vscode.window.showQuickPick(options, { placeHolder: prompt });
    return selection ? selection.value : "AES"; // Default to AES if no selection is made
}

// Encrypt text using the selected algorithm
function encryptText(text: string, key: string, algorithm: string): string {
    switch (algorithm) {
        case "TripleDES":
            return CryptoJS.TripleDES.encrypt(text, key).toString();
        case "RC4":
            return CryptoJS.RC4.encrypt(text, key).toString();
        case "AES":
        default:
            return CryptoJS.AES.encrypt(text, key).toString();
        case "RSA":
            return rsaEncrypt(text, key);
        case "Blowfish":
            return CryptoJS.Blowfish.encrypt(text, key).toString();
        case "Twofish":
            return CryptoJS.Twofish.encrypt(text, key).toString();
    }
}

// Decrypt text using the selected algorithm
function decryptText(text: string, key: string, algorithm: string): string {
    switch (algorithm) {
        case "TripleDES":
            return CryptoJS.TripleDES.decrypt(text, key).toString(CryptoJS.enc.Utf8);
        case "RC4":
            return CryptoJS.RC4.decrypt(text, key).toString(CryptoJS.enc.Utf8);
        case "AES":
        default:
            return CryptoJS.AES.decrypt(text, key).toString(CryptoJS.enc.Utf8);
        case "RSA":
            return rsaDecrypt(text, key);
    }
}

// Hash text using the selected algorithm
function hashText(text: string, algorithm: string): string {
    switch (algorithm) {
        case "SHA512":
            return CryptoJS.SHA512(text).toString();
        case "SHA256":
            return CryptoJS.SHA256(text).toString();
        case "MD5":
            return CryptoJS.MD5(text).toString();
        case "HMAC":
            return CryptoJS.HmacSHA256(text, "secret").toString();
        default:
            return CryptoJS.SHA256(text).toString();
    }
}

// RSA Encryption (using node-forge)
function rsaEncrypt(text: string, publicKeyPem: string): string {
    const publicKey = forge.pki.publicKeyFromPem(publicKeyPem);
    return forge.util.encode64(publicKey.encrypt(text));
}

// RSA Decryption (using node-forge)
function rsaDecrypt(text: string, privateKeyPem: string): string {
    const privateKey = forge.pki.privateKeyFromPem(privateKeyPem);
    return privateKey.decrypt(forge.util.decode64(text));
}

export function deactivate() {}
