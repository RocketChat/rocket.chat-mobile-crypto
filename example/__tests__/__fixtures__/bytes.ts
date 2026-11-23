export const bufferFromBase64 = (base64: string): ArrayBuffer => {
  const binary = atob(base64);
  const bytes = new Uint8Array(binary.length);
  for (let index = 0; index < binary.length; index++) {
    bytes[index] = binary.charCodeAt(index);
  }
  return bytes.buffer;
};

export const base64FromBuffer = (buffer: ArrayBuffer): string => {
  const bytes = new Uint8Array(buffer);
  let binary = '';
  for (let index = 0; index < bytes.length; index++) {
    binary += String.fromCharCode(bytes[index]!);
  }
  return btoa(binary);
};

export const bufferFromHex = (hex: string): ArrayBuffer => {
  const bytes = new Uint8Array(hex.length / 2);
  for (let index = 0; index < bytes.length; index++) {
    bytes[index] = parseInt(hex.slice(index * 2, index * 2 + 2), 16);
  }
  return bytes.buffer;
};

export const hexFromBuffer = (buffer: ArrayBuffer): string =>
  Array.from(new Uint8Array(buffer), (byte) =>
    byte.toString(16).padStart(2, '0')
  ).join('');

export const bufferFromAscii = (text: string): ArrayBuffer =>
  bufferFromBase64(btoa(text));

export const toStandardAlphabet = (base64Url: string): string =>
  base64Url.replace(/-/g, '+').replace(/_/g, '/');

export const toBase64UrlAlphabet = (base64: string): string =>
  base64.replace(/\+/g, '-').replace(/\//g, '_');

export const withoutPadding = (base64: string): string =>
  base64.replace(/[=]+$/, '');

export const wrapLines = (base64: string): string =>
  `${base64.slice(0, 8)}\n${base64.slice(8)}`;
