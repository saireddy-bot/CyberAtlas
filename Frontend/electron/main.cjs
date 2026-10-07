const { app, BrowserWindow, ipcMain, dialog } = require("electron");
const path = require("path");
const { spawn } = require("child_process");
const http = require("http");

let mainWindow = null;
let backendProcess = null;

const BACKEND_PORT = 8000;
const HEALTH_URL = `http://127.0.0.1:${BACKEND_PORT}/api/health`;
const APP_URL = `http://127.0.0.1:${BACKEND_PORT}`;

// Helper: Check if backend is alive
function checkBackendReady(timeoutMs = 15000) {
  const startTime = Date.now();
  return new Promise((resolve, reject) => {
    const interval = setInterval(() => {
      http.get(HEALTH_URL, (res) => {
        if (res.statusCode === 200) {
          clearInterval(interval);
          resolve(true);
        }
      }).on("error", () => {
        if (Date.now() - startTime > timeoutMs) {
          clearInterval(interval);
          resolve(false); // timeout, try loading anyway
        }
      });
    }, 500);
  });
}

// Helper: Spawn Python Backend if not already running
function startBackendIfNeeded() {
  return new Promise((resolve) => {
    http.get(HEALTH_URL, (res) => {
      if (res.statusCode === 200) {
        console.log("[CyberAtlas Desktop] Existing backend engine detected.");
        resolve();
      }
    }).on("error", () => {
      console.log("[CyberAtlas Desktop] Spawning dedicated backend engine...");
      const projectRoot = path.resolve(__dirname, "..", "..");
      const pythonExe = path.join(projectRoot, "Backend", "venv", "Scripts", "python.exe");

      backendProcess = spawn(
        pythonExe,
        ["-m", "uvicorn", "app.main:app", "--host", "127.0.0.1", "--port", String(BACKEND_PORT)],
        {
          cwd: path.join(projectRoot, "Backend"),
          stdio: "ignore",
          detached: false,
          windowsHide: true
        }
      );

      backendProcess.on("error", (err) => {
        console.error("[CyberAtlas Desktop] Backend spawn error:", err);
      });

      resolve();
    });
  });
}

function createMainWindow() {
  const iconPath = path.resolve(__dirname, "..", "..", "cyberatlas.ico");
  mainWindow = new BrowserWindow({
    width: 1440,
    height: 900,
    minWidth: 1024,
    minHeight: 720,
    title: "CyberAtlas — Autonomous Enterprise SOC Platform",
    backgroundColor: "#070b14",
    icon: iconPath,
    show: false,
    webPreferences: {
      preload: path.join(__dirname, "preload.cjs"),
      contextIsolation: true,
      nodeIntegration: false,
      sandbox: true
    }
  });

  // Remove standard browser menu for full application look & feel
  mainWindow.setMenuBarVisibility(false);


  mainWindow.once("ready-to-show", () => {
    mainWindow.maximize();
    mainWindow.show();
  });

  // IPC handlers
  ipcMain.on("window-minimize", () => mainWindow?.minimize());
  ipcMain.on("window-maximize", () => {
    if (mainWindow?.isMaximized()) {
      mainWindow.unmaximize();
    } else {
      mainWindow?.maximize();
    }
  });
  ipcMain.on("window-close", () => mainWindow?.close());

  mainWindow.on("closed", () => {
    mainWindow = null;
  });
}

app.whenReady().then(async () => {
  createMainWindow();
  await startBackendIfNeeded();
  await checkBackendReady();
  
  if (mainWindow) {
    mainWindow.loadURL(APP_URL);
  }
});

app.on("window-all-closed", () => {
  if (backendProcess) {
    try {
      process.kill(backendProcess.pid);
    } catch (e) {}
  }
  if (process.platform !== "darwin") {
    app.quit();
  }
});

app.on("quit", () => {
  if (backendProcess) {
    try {
      process.kill(backendProcess.pid);
    } catch (e) {}
  }
});
