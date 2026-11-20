import dotenv from "dotenv";

// Load environment variables before initializing the app
dotenv.config();

import { validateJwtConfiguration } from "./utils/jwt.js";

// Validate mandatory security configuration at boot
validateJwtConfiguration();

import app from "./app.js";

const PORT = Number(process.env.PORT) || 5000;
const NODE_ENV = process.env.NODE_ENV || "development";

const server = app.listen(PORT, () => {
  console.log(`[VaultGuard] Server running in ${NODE_ENV} mode on port ${PORT}`);
  console.log(`[VaultGuard] Root endpoint: http://localhost:${PORT}/`);
  console.log(`[VaultGuard] Health check: http://localhost:${PORT}/api/health`);
});

// Server-level error handling
server.on("error", (error: NodeJS.ErrnoException) => {
  if (error.syscall !== "listen") {
    throw error;
  }

  switch (error.code) {
    case "EACCES":
      console.error(`[VaultGuard] Port ${PORT} requires elevated privileges.`);
      process.exit(1);
    case "EADDRINUSE":
      console.error(`[VaultGuard] Port ${PORT} is already in use.`);
      process.exit(1);
    default:
      console.error("[VaultGuard] Server startup error:", error);
      process.exit(1);
  }
});

// Graceful shutdown handling
const handleGracefulShutdown = (signal: string) => {
  console.log(`\n[VaultGuard] Received ${signal}. Closing HTTP server gracefully...`);

  server.close((err) => {
    if (err) {
      console.error("[VaultGuard] Error during server shutdown:", err);
      process.exit(1);
    }
    console.log("[VaultGuard] HTTP server closed successfully.");
    process.exit(0);
  });

  // Force termination if connections do not close in time
  const timeoutMs = 10000;
  setTimeout(() => {
    console.error(`[VaultGuard] Shutdown timed out after ${timeoutMs}ms. Forcing exit.`);
    process.exit(1);
  }, timeoutMs).unref();
};

process.on("SIGTERM", () => handleGracefulShutdown("SIGTERM"));
process.on("SIGINT", () => handleGracefulShutdown("SIGINT"));

process.on("unhandledRejection", (reason: unknown) => {
  console.error("[VaultGuard] Unhandled Rejection:", reason);
  handleGracefulShutdown("unhandledRejection");
});

process.on("uncaughtException", (error: Error) => {
  console.error("[VaultGuard] Uncaught Exception:", error);
  handleGracefulShutdown("uncaughtException");
});
