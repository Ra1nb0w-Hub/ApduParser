"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
const electron_1 = require("electron");
electron_1.contextBridge.exposeInMainWorld('electronApi', {
    saveHtml: (html) => electron_1.ipcRenderer.invoke('save-html', html)
});
