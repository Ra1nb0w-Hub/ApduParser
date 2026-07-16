/// <reference types="vite/client" />

declare global {
  interface Window {
    electronApi?: {
      saveHtml: (html: string) => Promise<{ canceled: boolean; filePath?: string }>;
    };
  }
}

export {};
