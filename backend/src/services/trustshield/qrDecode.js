import { Jimp } from 'jimp';
import jsQR from 'jsqr';

// Decode a QR code from an image buffer. Treats the image as untrusted input
// and NEVER navigates to the decoded destination.
export async function decodeQrBuffer(buffer) {
  const image = await Jimp.read(buffer);
  const { data, width, height } = image.bitmap;
  const result = jsQR(new Uint8ClampedArray(data.buffer, data.byteOffset, data.length), width, height);
  return result ? result.data : null;
}
