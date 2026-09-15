import '@testing-library/jest-dom';
import { TextEncoder, TextDecoder } from 'util';

// jsdom (jest-environment-jsdom 29) doesn't expose TextEncoder/TextDecoder, and
// react-router-dom 7 reads them at import time — without this, every suite that
// pulls in a routed component dies while loading the module graph.
if (typeof globalThis.TextEncoder === 'undefined') {
  Object.assign(globalThis, { TextEncoder, TextDecoder });
}

// jsdom doesn't implement URL.createObjectURL/revokeObjectURL.
// SkillResources tests exercise blob-download paths that touch these.
if (typeof window.URL.createObjectURL === 'undefined') {
  window.URL.createObjectURL = jest.fn(() => 'blob:mock');
  window.URL.revokeObjectURL = jest.fn();
}
