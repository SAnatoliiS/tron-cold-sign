import "@testing-library/jest-dom";
import { Buffer } from "buffer";

globalThis.Buffer = Buffer;

/** jsdom File may lack arrayBuffer(); production browsers have it. */
if (
  typeof File !== "undefined" &&
  typeof File.prototype.arrayBuffer !== "function"
) {
  File.prototype.arrayBuffer = function arrayBufferPolyfill(this: File) {
    return new Promise((resolve, reject) => {
      const fr = new FileReader();
      fr.onload = () => resolve(fr.result as ArrayBuffer);
      fr.onerror = () => reject(fr.error);
      fr.readAsArrayBuffer(this);
    });
  };
}

Object.defineProperty(window, "matchMedia", {
  writable: true,
  value: (query: string) => ({
    matches: false,
    media: query,
    onchange: null,
    addListener: () => {},
    removeListener: () => {},
    addEventListener: () => {},
    removeEventListener: () => {},
    dispatchEvent: () => {},
  }),
});
