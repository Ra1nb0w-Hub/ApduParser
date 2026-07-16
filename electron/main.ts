import { app, BrowserWindow, dialog, ipcMain } from 'electron';
import { writeFile } from 'node:fs/promises';
import path from 'node:path';

const isDev = !app.isPackaged;
const appIcon = isDev ? path.join(__dirname, '../app.ico') : path.join(process.resourcesPath, 'app.ico');

app.setAppUserModelId('com.apduparser.desktop');

function createWindow() {
  const win = new BrowserWindow({
    width: 1200,
    height: 800,
    minWidth: 960,
    minHeight: 640,
    title: 'ApduParser',
    icon: appIcon,
    webPreferences: {
      preload: path.join(__dirname, 'preload.js'),
      contextIsolation: true,
      nodeIntegration: false
    }
  });
  win.setMenuBarVisibility(false);

  if (isDev) {
    win.loadURL('http://localhost:5177');
  } else {
    win.loadFile(path.join(__dirname, '../dist/index.html'));
  }
}

app.whenReady().then(createWindow);

app.on('window-all-closed', () => {
  if (process.platform !== 'darwin') {
    app.quit();
  }
});

app.on('activate', () => {
  if (BrowserWindow.getAllWindows().length === 0) {
    createWindow();
  }
});

ipcMain.handle('save-html', async (_event, html: string) => {
  const { canceled, filePath } = await dialog.showSaveDialog({
    title: '导出HTML报告',
    defaultPath: 'apdu_report.html',
    filters: [{ name: 'HTML文件', extensions: ['html'] }]
  });

  if (canceled || !filePath) {
    return { canceled: true };
  }

  await writeFile(filePath, html, 'utf8');
  return { canceled: false, filePath };
});
