"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
const electron_1 = require("electron");
const promises_1 = require("node:fs/promises");
const node_path_1 = __importDefault(require("node:path"));
const isDev = !electron_1.app.isPackaged;
const appIcon = isDev ? node_path_1.default.join(__dirname, '../app.ico') : node_path_1.default.join(process.resourcesPath, 'app.ico');
electron_1.app.setAppUserModelId('com.apduparser.desktop');
function createWindow() {
    const win = new electron_1.BrowserWindow({
        width: 1200,
        height: 800,
        minWidth: 960,
        minHeight: 640,
        title: 'ApduParser',
        icon: appIcon,
        webPreferences: {
            preload: node_path_1.default.join(__dirname, 'preload.js'),
            contextIsolation: true,
            nodeIntegration: false
        }
    });
    win.setMenuBarVisibility(false);
    if (isDev) {
        win.loadURL('http://localhost:5177');
    }
    else {
        win.loadFile(node_path_1.default.join(__dirname, '../dist/index.html'));
    }
}
electron_1.app.whenReady().then(createWindow);
electron_1.app.on('window-all-closed', () => {
    if (process.platform !== 'darwin') {
        electron_1.app.quit();
    }
});
electron_1.app.on('activate', () => {
    if (electron_1.BrowserWindow.getAllWindows().length === 0) {
        createWindow();
    }
});
electron_1.ipcMain.handle('save-html', async (_event, html) => {
    const { canceled, filePath } = await electron_1.dialog.showSaveDialog({
        title: '导出HTML报告',
        defaultPath: 'apdu_report.html',
        filters: [{ name: 'HTML文件', extensions: ['html'] }]
    });
    if (canceled || !filePath) {
        return { canceled: true };
    }
    await (0, promises_1.writeFile)(filePath, html, 'utf8');
    return { canceled: false, filePath };
});
