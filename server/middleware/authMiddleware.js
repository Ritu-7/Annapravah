const admin = require("../config/firebaseAdmin");

const IS_DEV = process.env.NODE_ENV !== "production";

const protect = async (req, res, next) => {
  let token;

  if (
    req.headers.authorization &&
    req.headers.authorization.startsWith("Bearer ")
  ) {
    try {
      token = req.headers.authorization.split(" ")[1];

      if (!token || token.trim() === "") {
        res.status(401);
        throw new Error("Unauthorized - Bearer token is empty");
      }

      // -----------------------------------------------------------------------
      // DEVELOPMENT-ONLY fallback paths.
      // These branches are NEVER reached in production (NODE_ENV === "production")
      // so dev tokens and unverified JWT decodes cannot bypass auth in prod.
      // -----------------------------------------------------------------------
      if (IS_DEV) {
        // Allow explicit dev/mock tokens (e.g. from local testing scripts)
        if (token.startsWith("dev-") || token.startsWith("mock-")) {
          const devEmail =
            token.length < 20
              ? `${token}@replate.org`
              : "dev.partner@replate.org";
          req.user = {
            uid: token,
            firebaseUid: token,
            email: devEmail,
            name: "Dev Partner User",
          };
          return next();
        }

        // Allow startup without Firebase credentials in dev (no private key set)
        if (!process.env.FIREBASE_PRIVATE_KEY) {
          req.user = {
            uid: token,
            firebaseUid: token,
            email: "dev.partner@replate.org",
            name: "Dev Partner User (no Firebase key)",
          };
          return next();
        }
      }

      // -----------------------------------------------------------------------
      // PRIMARY PATH (all environments): strict Firebase Admin SDK verification.
      // -----------------------------------------------------------------------
      try {
        const decodedToken = await admin.auth().verifyIdToken(token);
        req.user = {
          uid: decodedToken.uid,
          firebaseUid: decodedToken.uid,
          email: decodedToken.email,
          name: decodedToken.name || decodedToken.email?.split("@")[0],
          picture: decodedToken.picture || "",
        };
        return next();
      } catch (verifyError) {
        // -----------------------------------------------------------------------
        // DEVELOPMENT-ONLY fallback: if Firebase verification fails in dev
        // (e.g. clock skew, missing emulator config), attempt a manual JWT decode
        // so local developers are not blocked. This path is NEVER taken in prod.
        // -----------------------------------------------------------------------
        if (IS_DEV) {
          console.warn(
            "[DEV] Firebase token verification failed — attempting manual decode:",
            verifyError.message
          );

          try {
            // Raw UID from localStorage fallback (not a JWT)
            if (!token.includes(".")) {
              req.user = {
                uid: token,
                firebaseUid: token,
                email: `fallback-${token.slice(0, 10)}@replate.org`,
                name: "Fallback User",
              };
              return next();
            }

            // Decode JWT payload WITHOUT signature verification (dev only)
            const base64Url = token.split(".")[1];
            const base64 = base64Url.replace(/-/g, "+").replace(/_/g, "/");
            const jsonPayload = Buffer.from(base64, "base64").toString("utf8");
            const payload = JSON.parse(jsonPayload);

            req.user = {
              uid: payload.user_id || token,
              firebaseUid: payload.user_id || token,
              email: payload.email || "dev.user@replate.org",
              name:
                payload.name || payload.email?.split("@")[0] || "Dev User",
            };
            return next();
          } catch (decodeErr) {
            console.error("[DEV] Manual JWT decode failed:", decodeErr.message);
            res.status(401);
            return next(new Error("Unauthorized - Invalid or expired token"));
          }
        }

        // Production: verification failed → reject immediately.
        console.error(
          "[PROD] Firebase token verification failed:",
          verifyError.message
        );
        res.status(401);
        return next(
          new Error("Unauthorized - Invalid or expired authentication token")
        );
      }
    } catch (error) {
      console.error("Auth Middleware caught unexpected error:", error.message);
      res.status(401);
      return next(error);
    }
  }

  res.status(401);
  return next(new Error("Unauthorized - Missing Bearer authorization header"));
};

const verifiedOnly = async (req, res, next) => {
  try {
    const User = require("../models/User");
    const firebaseUid = req.user?.uid || req.user?.firebaseUid;

    if (!firebaseUid) {
      res.status(401);
      throw new Error("Unauthorized - User identity missing");
    }

    const mongoUser = await User.findOne({ firebaseUid });
    if (!mongoUser) {
      res.status(401);
      throw new Error(
        `Unauthorized - User not found in system (UID: ${firebaseUid})`
      );
    }

    if (!mongoUser.isVerified && mongoUser.role !== "ADMIN") {
      res.status(403);
      throw new Error(
        "Forbidden - Your account is pending verification by an administrator. You cannot perform this action yet."
      );
    }

    req.mongoUser = mongoUser;
    next();
  } catch (error) {
    next(error);
  }
};

const optionalAuth = async (req, res, next) => {
  if (
    req.headers.authorization &&
    req.headers.authorization.startsWith("Bearer ")
  ) {
    try {
      // Re-use protect logic but trap any errors so the route still proceeds
      const mockRes = {
        status: () => mockRes,
        json: () => {},
      };

      let errorThrown = null;
      const mockNext = (err) => {
        if (err) errorThrown = err;
      };

      await protect(req, mockRes, mockNext);

      // If protect attached req.user and didn't throw — great.
      // If it threw, we silently ignore it and leave req.user undefined.
    } catch (err) {
      // ignore
    }
  }
  next();
};

module.exports = {
  protect,
  verifiedOnly,
  optionalAuth,
};
