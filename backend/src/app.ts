import express, { type Express, type Request, type Response } from "express";
import cors from "cors";
import helmet from "helmet";
import cookieParser from "cookie-parser";
import { errorHandler, notFoundHandler } from "./middleware/errorHandler.js";
import authRoutes from "./routes/authRoutes.js";
import vaultRoutes from "./routes/vaultRoutes.js";
import deviceRoutes from "./routes/deviceRoutes.js";
import syncRoutes from "./routes/syncRoutes.js";

const app: Express = express();

// Security Headers
app.use(helmet());

// CORS Configuration — credentials: true required for HttpOnly cookie exchange
const frontendUrl = process.env.FRONTEND_URL || "http://localhost:3000";
app.use(
  cors({
    origin: frontendUrl,
    credentials: true,
    methods: ["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"],
    allowedHeaders: ["Content-Type", "Authorization", "X-VaultGuard-Request"]
  })
);

// Body Parsing Middleware (2mb allows encrypted payloads up to 1 MiB raw with JSON and Base64 overhead)
app.use(express.json({ limit: "2mb" }));

// Cookie Parser — required for HttpOnly refresh token cookie handling (Phase 6)
app.use(cookieParser());

// Root Endpoint
app.get("/", (_req: Request, res: Response) => {
  res.status(200).json({
    success: true,
    message: "Welcome to VaultGuard API",
    version: "1.0.0"
  });
});

// Health-Check Endpoint
app.get("/api/health", (_req: Request, res: Response) => {
  res.status(200).json({
    success: true,
    message: "VaultGuard backend is running",
    timestamp: new Date().toISOString()
  });
});

// Authentication Routes
app.use("/api/auth", authRoutes);

// Zero-Knowledge Encrypted Vault Routes
app.use("/api/vault", vaultRoutes);

// Device Management Routes (Phase 6)
app.use("/api/devices", deviceRoutes);

// Encrypted Vault Synchronization Routes (Phase 7)
app.use("/api/sync", syncRoutes);

// 404 Route Handler
app.use(notFoundHandler);

// Centralized Error Handler
app.use(errorHandler);

export default app;
