const express = require("express");
const router = express.Router();
const { protect } = require("../middleware/authMiddleware");
const { adminOnly } = require("../middleware/adminMiddleware");

/**
 * GET /api/debug/env
 *
 * Returns environment diagnostics for admin operators.
 * Locked behind protect + adminOnly — regular users and unauthenticated
 * callers receive a 401/403 and never see SUPER_ADMIN_EMAIL.
 *
 * NOTE: In production you may want to remove this route entirely or
 * further restrict it to a maintenance IP allowlist.
 */
router.get("/env", protect, adminOnly, (req, res) => {
  res.json({
    hasSuperAdmin: !!process.env.SUPER_ADMIN_EMAIL,
    // Mask the email in the response — admins only need to know it is set.
    superAdminEmail: process.env.SUPER_ADMIN_EMAIL
      ? process.env.SUPER_ADMIN_EMAIL.replace(
          /^(.{2})(.*)(@.*)$/,
          (_, a, b, c) => a + "*".repeat(b.length) + c
        )
      : "not configured",
    hasFirebaseKey: !!process.env.FIREBASE_PRIVATE_KEY,
    nodeEnv: process.env.NODE_ENV || "development",
  });
});

module.exports = router;
