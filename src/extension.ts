import * as vscode from 'vscode';
import * as CryptoJS from 'crypto-js';
import * as forge from 'node-forge';

// Register commands for encryption, decryption, and hashing
export function activate(context: vscode.ExtensionContext) {
  let disposableEncrypt = vscode.commands.registerCommand('inlineCrypto.encrypt', async () => {
    const editor = vscode.window.activeTextEditor;
    if (editor && editor.selection) {
      const selectedText = editor.document.getText(editor.selection);
      const algorithm = await vscode.window.showQuickPick(['AES', 'Blowfish', 'RSA', 'Base64', 'Base32'], { placeHolder: 'Select encryption method' });
      const key = algorithm !== 'Base64' && algorithm !== 'Base32' ? await vscode.window.showInputBox({ placeHolder: 'Enter encryption key' }) : '';

      if (selectedText && algorithm) {
        const encryptedText = encryptText(selectedText, key || '', algorithm);
        editor.edit(editBuilder => {
          editBuilder.replace(editor.selection, encryptedText);
        });
      }
    }
  });

  let disposableDecrypt = vscode.commands.registerCommand('inlineCrypto.decrypt', async () => {
    const editor = vscode.window.activeTextEditor;
    if (editor && editor.selection) {
      const selectedText = editor.document.getText(editor.selection);
      const algorithm = await vscode.window.showQuickPick(['AES', 'Blowfish', 'RSA', 'Base64', 'Base32'], { placeHolder: 'Select decryption method' });
      const key = algorithm !== 'Base64' && algorithm !== 'Base32' ? await vscode.window.showInputBox({ placeHolder: 'Enter decryption key' }) : '';

      if (selectedText && algorithm) {
        const decryptedText = decryptText(selectedText, key || '', algorithm);
        editor.edit(editBuilder => {
          editBuilder.replace(editor.selection, decryptedText);
        });
      }
    }
  });

  let disposableHash = vscode.commands.registerCommand('inlineCrypto.hash', async () => {
    const editor = vscode.window.activeTextEditor;
    if (editor && editor.selection) {
      const selectedText = editor.document.getText(editor.selection);
      const algorithm = await vscode.window.showQuickPick(['SHA256', 'SHA512', 'MD5'], { placeHolder: 'Select hashing method' });

      if (selectedText && algorithm) {
        const hashedText = hashText(selectedText, algorithm);
        editor.edit(editBuilder => {
          editBuilder.replace(editor.selection, hashedText);
        });
      }
    }
  });

  context.subscriptions.push(disposableEncrypt, disposableDecrypt, disposableHash);
}

// Encrypt text based on selected algorithm
function encryptText(text: string, key: string, algorithm: string): string {
  switch (algorithm) {
    case 'AES':
      return CryptoJS.AES.encrypt(text, key).toString();
    case 'Blowfish':
      return CryptoJS.Blowfish.encrypt(text, key).toString();
    case 'RSA':
      return rsaEncrypt(text, key); // RSA encryption needs a key
    case 'Base64':
      return CryptoJS.enc.Base64.stringify(CryptoJS.enc.Utf8.parse(text)); // No key needed
    case 'Base32':
      return base32Encode(text); // No key needed
    default:
      return CryptoJS.AES.encrypt(text, key).toString(); // Default to AES
  }
}

// Decrypt text based on selected algorithm
function decryptText(text: string, key: string, algorithm: string): string {
  switch (algorithm) {
    case 'AES':
      return CryptoJS.AES.decrypt(text, key).toString(CryptoJS.enc.Utf8);
    case 'Blowfish':
      return CryptoJS.Blowfish.decrypt(text, key).toString(CryptoJS.enc.Utf8);
    case 'RSA':
      return rsaDecrypt(text, key); // RSA decryption needs a key
    case 'Base64':
      return CryptoJS.enc.Base64.parse(text).toString(CryptoJS.enc.Utf8); // No key needed
    case 'Base32':
      return base32Decode(text); // No key needed
    default:
      return CryptoJS.AES.decrypt(text, key).toString(CryptoJS.enc.Utf8); // Default to AES
  }
}

// Hash text based on selected algorithm
function hashText(text: string, algorithm: string): string {
  switch (algorithm) {
    case 'SHA256':
      return CryptoJS.SHA256(text).toString();
    case 'SHA512':
      return CryptoJS.SHA512(text).toString();
    case 'MD5':
      return CryptoJS.MD5(text).toString();
    default:
      return CryptoJS.SHA256(text).toString(); // Default to SHA256
  }
}

// RSA encryption (using node-forge)
function rsaEncrypt(text: string, publicKeyPem: string): string {
  const publicKey = forge.pki.publicKeyFromPem(publicKeyPem);
  return forge.util.encode64(publicKey.encrypt(text));
}

// RSA decryption (using node-forge)
function rsaDecrypt(text: string, privateKeyPem: string): string {
  const privateKey = forge.pki.privateKeyFromPem(privateKeyPem);
  return privateKey.decrypt(forge.util.decode64(text));
}

// Base32 Encoding
function base32Encode(text: string): string {
  const alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
  const input = Buffer.from(text, 'utf8');
  let bits = '';
  input.forEach(byte => {
    bits += byte.toString(2).padStart(8, '0');
  });
  while (bits.length % 5 !== 0) {
    bits += '0'; // Padding
  }
  const chunks = bits.match(/.{5}/g);
  return chunks ? chunks.map(chunk => alphabet[parseInt(chunk, 2)]).join('') : '';
}

// Base32 Decoding
function base32Decode(encoded: string): string {
  const alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
  let bits = '';
  encoded.toUpperCase().split('').forEach(char => {
    if (char !== '=') {
      const index = alphabet.indexOf(char);
      bits += index.toString(2).padStart(5, '0');
    }
  });
  let decoded = '';
  for (let i = 0; i < bits.length; i += 8) {
    decoded += String.fromCharCode(parseInt(bits.substr(i, 8), 2));
  }
  return decoded;
}

export function deactivate() {}
