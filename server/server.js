const express = require("express");
const cors = require("cors");
const helmet = require("helmet");
const mongoSanitize = require("express-mongo-sanitize");
const rateLimit = require("express-rate-limit");
const dotenv = require("dotenv");

// Load Environment Variables FIRST before importing anything else
dotenv.config();

const connectDB = require("./config/db");

// Import Middleware
const { notFound, errorHandler } = require("./middleware/error.middleware");

// Import Route Modules
const healthRoutes = require("./routes/health.routes");
const authRoutes = require("./routes/auth.routes");
const userRoutes = require("./routes/user.routes");
const foodRoutes = require("./routes/foodRoutes");
const businessRoutes = require("./routes/businessRoutes");
const recipientRoutes = require("./routes/recipientRoutes");
const reservationRoutes = require("./routes/reservation.routes");
const adminRoutes = require("./routes/adminRoutes");
const analyticsRoutes = require("./routes/analytics.routes");
const notificationRoutes = require("./routes/notification.routes");
const aiRoutes = require("./routes/ai.routes");
const impactRoutes = require("./routes/impactRoutes");
const uploadRoutes = require("./routes/uploadRoutes");
const path = require("path");

// Import Background Job Modules
const { startExpiryBackgroundJob } = require("./jobs/expiryJob");
const startEscalationJob = require("./jobs/escalationJob");

const app = express();
const PORT = process.env.PORT || 5000;

// Connect to MongoDB Atlas
connectDB();

// ---------------------------------------------------------------------------
// Security: Helmet — sets various HTTP security headers.
// crossOriginResourcePolicy: false keeps /uploads images publicly accessible
// from the React client's <img> tags without CORP errors.
// ---------------------------------------------------------------------------
app.use(helmet({ crossOriginResourcePolicy: false }));

// ---------------------------------------------------------------------------
// Security: CORS — strict origin whitelist.
// Allows the Vite dev server, a local backend proxy, and the deployed client.
// Requests with no Origin header (mobile apps, Postman, curl) are permitted.
// ---------------------------------------------------------------------------
const allowedOrigins = [
  "http://localhost:5173",
  "http://localhost:3000",
  process.env.CLIENT_URL,
].filter(Boolean); // remove undefined if CLIENT_URL is not set

app.use(
  cors({
    origin: (origin, callback) => {
      // Allow requests with no origin (mobile / Postman / server-to-server)
      if (!origin) return callback(null, true);
      if (allowedOrigins.includes(origin)) return callback(null, true);
      callback(new Error(`CORS policy: origin '${origin}' is not allowed`));
    },
    credentials: true,
  })
);

// ---------------------------------------------------------------------------
// Security: NoSQL Injection Protection — strips $ and . keys from req.body,
// req.query, and req.params before they reach Mongoose queries.
// ---------------------------------------------------------------------------
app.use(mongoSanitize());

app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// ---------------------------------------------------------------------------
// Rate Limiting
// General limiter: 100 requests per 15 minutes per IP on all /api routes.
// AI limiter:      10 requests per minute per IP on /api/ai to protect the
//                  Gemini quota from being exhausted by a single caller.
// ---------------------------------------------------------------------------
const generalLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 100,
  standardHeaders: true,
  legacyHeaders: false,
  message: {
    success: false,
    message: "Too many requests. Please slow down and try again in 15 minutes.",
  },
});

const aiLimiter = rateLimit({
  windowMs: 60 * 1000, // 1 minute
  max: 10,
  standardHeaders: true,
  legacyHeaders: false,
  message: {
    success: false,
    message: "AI rate limit reached. Maximum 10 requests per minute allowed.",
  },
});

// Apply AI limiter BEFORE the general limiter so its stricter window wins
app.use("/api/ai", aiLimiter);
app.use("/api", generalLimiter);

// Serve Static Uploads
app.use("/uploads", express.static(path.join(__dirname, "uploads")));

// Mount API Domain Routes
app.use("/api", healthRoutes);
app.use("/api/debug", require("./routes/debug.routes"));
app.use("/api/auth", authRoutes);
app.use("/api/users", userRoutes);
app.use("/api/food", foodRoutes);
app.use("/api/businesses", businessRoutes);
app.use("/api/recipients", recipientRoutes);
app.use("/api/reservations", reservationRoutes);
app.use("/api/notifications", notificationRoutes);
app.use("/api/admin", adminRoutes);
app.use("/api/analytics", analyticsRoutes);
app.use("/api/ai", aiRoutes);
app.use("/api/impact", impactRoutes);
app.use("/api/uploads", uploadRoutes);

// Root Welcome Endpoint
app.get("/", (req, res) => {
  res.status(200).json({
    success: true,
    message: "Welcome to RePlate API Platform",
    tagline: "Good food deserves another plate.",
  });
});

// Centralized 404 & Error Handlers
app.use(notFound);
app.use(errorHandler);

// Start Express Server
app.listen(PORT, "0.0.0.0", () => {
  console.log(`RePlate Express Server running on port ${PORT}`);
  // Start food status & expiry monitor background job
  startExpiryBackgroundJob();
  startEscalationJob();
});
