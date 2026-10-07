const { contextBridge, ipcRenderer } = require("electron");

contextBridge.exposeInMainWorld("cyberatlasDesktop", {
  isDesktop: true,
  appVersion: "1.0.0",
  platform: process.platform,
  minimize: () => ipcRenderer.send("window-minimize"),
  maximize: () => ipcRenderer.send("window-maximize"),
  close: () => ipcRenderer.send("window-close")
});
