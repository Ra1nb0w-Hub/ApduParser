import { contextBridge, ipcRenderer } from 'electron';

contextBridge.exposeInMainWorld('electronApi', {
  saveHtml: (html: string) => ipcRenderer.invoke('save-html', html)
});
