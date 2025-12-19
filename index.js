const express = require("express");
const cors = require("cors");
require("dotenv").config();
const { MongoClient, ObjectId } = require("mongodb");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const admin = require("firebase-admin");
const stripe = require("stripe")(process.env.STRIPE_SECRET_KEY);
const fs = require("fs-extra");
const path = require("path");
const multer = require("multer");

// ==================== CONFIGURATION ====================
const PORT = process.env.PORT || 5000;
const MONGO_URI = process.env.MONGO_URI;
const DB_NAME = process.env.DB_NAME || "contesthub";
const JWT_SECRET = process.env.JWT_SECRET;

if (!JWT_SECRET) throw new Error("JWT_SECRET is required");
if (!MONGO_URI) throw new Error("MONGO_URI is required");

const UPLOADS_DIR = path.join("/tmp", "uploads");
fs.ensureDirSync(UPLOADS_DIR);

// ==================== MULTER SETUP ====================
const storage = multer.diskStorage({
  destination: (req, file, cb) => cb(null, UPLOADS_DIR),
  filename: (req, file, cb) =>
    cb(null, `${Date.now()}-${file.originalname.replace(/\s+/g, "_")}`),
});
const upload = multer({
  storage: storage,
  limits: { fileSize: 10 * 1024 * 1024 },
});

// ==================== FIREBASE ADMIN ====================
try {
  if (process.env.FB_SERVICE_KEY) {
    const serviceAccount = JSON.parse(
      Buffer.from(process.env.FB_SERVICE_KEY, "base64").toString("utf8")
    );
    if (!admin.apps.length) {
      admin.initializeApp({
        credential: admin.credential.cert(serviceAccount),
      });
    }
    console.log("✅ Firebase Admin initialized from FB_SERVICE_KEY");
  } else if (process.env.GOOGLE_APPLICATION_CREDENTIALS) {
    const serviceAccount = require(process.env.GOOGLE_APPLICATION_CREDENTIALS);
    if (!admin.apps.length) {
      admin.initializeApp({
        credential: admin.credential.cert(serviceAccount),
      });
    }
    console.log(
      "✅ Firebase Admin initialized from GOOGLE_APPLICATION_CREDENTIALS"
    );
  } else {
    console.warn("⚠️ Firebase Admin not initialized - no credentials found");
  }
} catch (error) {
  console.error("❌ Firebase Admin error:", error.message);
}

// ==================== EXPRESS APP ====================
const app = express();

app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// ==================== CORS CONFIGURATION ====================
const allowedOrigins = [
  "http://localhost:5173",
  "http://localhost:3000",
  "http://localhost:5000",
  "https://contest-hub-the-best-contest-website.netlify.app",
  process.env.CLIENT_URL,
  process.env.SITE_DOMAIN,
].filter(Boolean);

console.log("🌐 Allowed CORS origins:", allowedOrigins);

app.use(
  cors({
    origin: function (origin, callback) {
      if (!origin) return callback(null, true);
      if (allowedOrigins.indexOf(origin) !== -1) {
        callback(null, true);
      } else {
        console.warn("⚠️ Blocked by CORS:", origin);
        callback(null, true);
      }
    },
    credentials: true,
    methods: ["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"],
    allowedHeaders: [
      "Content-Type",
      "Authorization",
      "X-Requested-With",
      "Accept",
      "Origin",
    ],
    exposedHeaders: ["Content-Length", "X-Request-Id"],
    maxAge: 86400,
    preflightContinue: false,
    optionsSuccessStatus: 204,
  })
);

// ==================== MONGODB CONNECTION ====================
let cachedDb = null;
let cachedClient = null;

async function connectToDatabase() {
  if (cachedDb && cachedClient) {
    return { db: cachedDb, client: cachedClient };
  }

  const client = await MongoClient.connect(MONGO_URI, {
    maxPoolSize: 10,
    serverSelectionTimeoutMS: 5000,
    socketTimeoutMS: 45000,
  });

  const db = client.db(DB_NAME);
  cachedClient = client;
  cachedDb = db;

  return { db, client };
}

// Global variables for collections
let Users, Contests, Registrations, Submissions;

async function ensureDbConnection(req, res, next) {
  try {
    if (!cachedDb) {
      const { db } = await connectToDatabase();
      Users = db.collection("users");
      Contests = db.collection("contests");
      Registrations = db.collection("registrations");
      Submissions = db.collection("submissions");

      await Promise.all([
        Users.createIndex({ email: 1 }, { unique: true }).catch(() => {}),
        Contests.createIndex({ creator: 1 }).catch(() => {}),
        Registrations.createIndex(
          { user: 1, contest: 1 },
          { unique: true }
        ).catch(() => {}),
        Submissions.createIndex({ contest: 1, user: 1 }).catch(() => {}),
      ]);
    }
    next();
  } catch (error) {
    console.error("❌ Database connection error:", error);
    res.status(500).json({ error: "Database connection failed" });
  }
}

app.use((req, res, next) => {
  if (req.path === "/" || req.path === "/health") {
    return next();
  }
  return ensureDbConnection(req, res, next);
});

// ==================== HELPER FUNCTIONS ====================
function signToken(user) {
  return jwt.sign(
    { id: user._id.toString(), role: user.role, email: user.email },
    JWT_SECRET,
    { expiresIn: "7d" }
  );
}

async function authMiddleware(req, res, next) {
  const auth = req.headers.authorization;
  if (!auth || !auth.startsWith("Bearer "))
    return res.status(401).json({ error: "Missing token" });

  try {
    const token = auth.split(" ")[1];
    const payload = jwt.verify(token, JWT_SECRET);
    const user = await Users.findOne({ _id: new ObjectId(payload.id) });
    if (!user) return res.status(401).json({ error: "User not found" });
    req.user = user;
    next();
  } catch {
    return res.status(401).json({ error: "Invalid token" });
  }
}

function requireRole(...roles) {
  return (req, res, next) => {
    if (!req.user) return res.status(401).json({ error: "Not authenticated" });
    if (!roles.includes(req.user.role) && req.user.role !== "admin")
      return res.status(403).json({ error: "Forbidden" });
    next();
  };
}

// ==================== HEALTH CHECK ====================
app.get("/", (req, res) => {
  res.json({
    status: "ok",
    message: "ContestHub API running",
    timestamp: new Date(),
    allowedOrigins: allowedOrigins.length,
  });
});

app.get("/health", (req, res) => {
  res.json({ ok: true, timestamp: new Date() });
});

// ==================== AUTH ROUTES ====================
app.post("/api/auth/register", async (req, res) => {
  try {
    const { name, email, password, role } = req.body;
    if (!name || !email || !password)
      return res.status(400).json({ error: "Required fields missing" });

    const hashed = await bcrypt.hash(password, 10);
    const userDoc = {
      name,
      email: email.toLowerCase(),
      password: hashed,
      role: role === "creator" ? "creator" : "user",
      photoURL: null,
      bio: null,
      address: null,
      participatedCount: 0,
      wonCount: 0,
      createdAt: new Date(),
    };

    const result = await Users.insertOne(userDoc);
    const user = await Users.findOne(
      { _id: result.insertedId },
      { projection: { password: 0 } }
    );
    const token = signToken(user);
    return res.json({ user: { ...user, id: user._id.toString() }, token });
  } catch (err) {
    if (err.code === 11000)
      return res.status(400).json({ error: "Email already registered" });
    res.status(500).json({ error: "Server error" });
  }
});

app.post("/api/auth/login", async (req, res) => {
  try {
    const { email, password } = req.body;
    const user = await Users.findOne({ email: email.toLowerCase() });
    if (!user) return res.status(400).json({ error: "Invalid credentials" });

    const match = await bcrypt.compare(password, user.password);
    if (!match) return res.status(400).json({ error: "Invalid credentials" });

    const token = signToken(user);
    return res.json({
      user: {
        id: user._id.toString(),
        name: user.name,
        email: user.email,
        role: user.role,
        photoURL: user.photoURL,
        createdAt: user.createdAt,
      },
      token,
    });
  } catch {
    res.status(500).json({ error: "Server error" });
  }
});

app.post("/api/auth/google", async (req, res) => {
  const { idToken } = req.body;

  console.log("🔐 Google auth request from:", req.headers.origin);

  if (!idToken) {
    return res.status(400).json({ error: "Missing idToken" });
  }

  try {
    const decodedToken = await admin.auth().verifyIdToken(idToken);
    const { uid, email, name, picture } = decodedToken;

    let user = await Users.findOne({ email: email.toLowerCase() });
    if (!user) {
      const userDoc = {
        name: name || email.split("@")[0],
        email: email.toLowerCase(),
        role: "user",
        photoURL: picture || null,
        bio: null,
        address: null,
        participatedCount: 0,
        wonCount: 0,
        firebaseUid: uid,
        createdAt: new Date(),
      };
      const result = await Users.insertOne(userDoc);
      user = await Users.findOne({ _id: result.insertedId });
    }

    const token = signToken(user);

    console.log("✅ Google auth successful for:", email);

    res.json({
      user: {
        id: user._id.toString(),
        name: user.name,
        email: user.email,
        role: user.role,
        photoURL: user.photoURL,
        createdAt: user.createdAt,
      },
      token,
    });
  } catch (err) {
    console.error("❌ Google auth error:", err);
    res.status(401).json({ error: "Invalid Firebase token" });
  }
});

app.get("/api/auth/me", authMiddleware, async (req, res) => {
  const {
    _id,
    name,
    email,
    role,
    photoURL,
    bio,
    address,
    participatedCount,
    wonCount,
    createdAt,
  } = req.user;
  res.json({
    user: {
      id: _id.toString(),
      name,
      email,
      role,
      photoURL,
      bio,
      address,
      participatedCount,
      wonCount,
      createdAt,
    },
  });
});

// ==================== USER ROUTES ====================
app.put("/api/users/me", authMiddleware, async (req, res) => {
  try {
    const { name, photoURL, bio, address } = req.body;
    const updates = {};
    if (name) updates.name = name;
    if (photoURL !== undefined) updates.photoURL = photoURL;
    if (bio !== undefined) updates.bio = bio;
    if (address !== undefined) updates.address = address;
    updates.updatedAt = new Date();

    await Users.updateOne(
      { _id: new ObjectId(req.user._id) },
      { $set: updates }
    );
    const user = await Users.findOne(
      { _id: new ObjectId(req.user._id) },
      { projection: { password: 0 } }
    );
    res.json({ user });
  } catch {
    res.status(500).json({ error: "Server error" });
  }
});

app.get("/api/users/profile", authMiddleware, async (req, res) => {
  try {
    const user = await Users.findOne(
      { _id: new ObjectId(req.user._id) },
      { projection: { password: 0 } }
    );
    res.json({ user });
  } catch {
    res.status(500).json({ error: "Server error" });
  }
});
app.put("/api/users/profile", authMiddleware, async (req, res) => {
  try {
    const { name, photoURL, bio, address } = req.body;
    const updates = {};
    if (name) updates.name = name;
    if (photoURL !== undefined) updates.photoURL = photoURL;
    if (bio !== undefined) updates.bio = bio;
    if (address !== undefined) updates.address = address;
    updates.updatedAt = new Date();

    await Users.updateOne(
      { _id: new ObjectId(req.user._id) },
      { $set: updates }
    );
    const user = await Users.findOne(
      { _id: new ObjectId(req.user._id) },
      { projection: { password: 0 } }
    );
    res.json({ user });
  } catch {
    res.status(500).json({ error: "Server error" });
  }
});

app.get(
  "/api/users/participated-contests",
  authMiddleware,
  async (req, res) => {
    try {
      const registrations = await Registrations.find({
        user: new ObjectId(req.user._id),
      }).toArray();

      const contests = await Promise.all(
        registrations.map(async (reg) => {
          const contest = await Contests.findOne({ _id: reg.contest });
          return contest;
        })
      );

      res.json({ contests: contests.filter(Boolean) });
    } catch {
      res.status(500).json({ error: "Server error" });
    }
  }
);

app.get("/api/users/won-contests", authMiddleware, async (req, res) => {
  try {
    const wins = await Submissions.find({
      user: new ObjectId(req.user._id),
      isWinner: true,
    }).toArray();

    const contests = await Promise.all(
      wins.map(async (w) => await Contests.findOne({ _id: w.contest }))
    );

    res.json({ contests: contests.filter(Boolean) });
  } catch {
    res.status(500).json({ error: "Server error" });
  }
});

// ==================== PAYMENT ROUTES ====================
app.post("/api/create-checkout-session", async (req, res) => {
  try {
    const { contestName, contestId, cost, senderEmail, senderId } = req.body;

    console.log("📍 Payment request:", {
      contestName,
      contestId,
      cost,
      senderEmail,
    });

    if (!contestName || !contestId || !senderEmail) {
      console.log("❌ Missing required fields");
      return res.status(400).json({
        error: "Missing payment fields",
        received: { contestName, contestId, cost, senderEmail },
      });
    }

    if (cost === undefined || cost === null) {
      console.log("❌ Cost is undefined");
      return res.status(400).json({ error: "Entry fee not specified" });
    }

    const amount = Number(cost) * 100;

    if (!Number.isInteger(amount) || amount <= 0) {
      console.log("❌ Invalid amount:", amount);
      return res.status(400).json({
        error: "Invalid amount",
        cost,
        calculatedAmount: amount,
      });
    }

    const siteDomain =
      process.env.SITE_DOMAIN ||
      (req.headers.origin?.includes("5173")
        ? req.headers.origin
        : "https://contest-hub-the-best-contest-website.netlify.app/");

    console.log("💳 Creating Stripe session...");

    const session = await stripe.checkout.sessions.create({
      payment_method_types: ["card"],
      line_items: [
        {
          price_data: {
            currency: "usd",
            unit_amount: amount,
            product_data: {
              name: contestName,
            },
          },
          quantity: 1,
        },
      ],
      mode: "payment",
      customer_email: senderEmail,
      metadata: { contestId, userId: senderId || "" },
      success_url: `${siteDomain}/dashboard/payment-success?session_id={CHECKOUT_SESSION_ID}`,
      cancel_url: `${siteDomain}/dashboard/payment-canceled`,
    });

    console.log("✅ Stripe session created:", session.id);
    res.json({ url: session.url });
  } catch (err) {
    console.error("❌ Stripe error:", err);
    res.status(400).json({
      error: err.message,
      details: "Failed to create checkout session",
    });
  }
});

app.patch("/api/payment-success", async (req, res) => {
  try {
    const sessionId = req.query.session_id;
    if (!sessionId)
      return res.status(400).json({ error: "Missing session_id" });

    const session = await stripe.checkout.sessions.retrieve(sessionId);
    if (!session) return res.status(404).json({ error: "Session not found" });

    const contestId = session.metadata?.contestId;
    const customerEmail =
      session.customer_email || session.customer_details?.email;

    if (!contestId || !customerEmail) {
      return res
        .status(400)
        .json({ error: "Missing contestId or customer email in session" });
    }

    // Find user
    let user = null;
    const metaUserId =
      session.metadata?.userId || session.metadata?.user_id || "";
    if (metaUserId && ObjectId.isValid(metaUserId)) {
      user = await Users.findOne({ _id: new ObjectId(metaUserId) });
    }
    if (!user && customerEmail) {
      user = await Users.findOne({ email: customerEmail.toLowerCase() });
    }
    if (!user && customerEmail) {
      const guest = {
        name:
          session.customer_details?.name ||
          session.customer_details?.email?.split("@")[0] ||
          "Guest",
        email: customerEmail.toLowerCase(),
        photoURL: session.customer_details?.name
          ? `https://ui-avatars.com/api/?name=${encodeURIComponent(
              session.customer_details.name
            )}`
          : "https://via.placeholder.com/48",
        role: "user",
        participatedCount: 0,
        wonCount: 0,
        createdAt: new Date(),
      };
      const r = await Users.insertOne(guest);
      guest._id = r.insertedId;
      user = guest;
      console.log("ℹ️ Created guest user for payment email", customerEmail);
    }
    if (!user) {
      console.warn("⚠️ Payment succeeded but user not found");
      return res.json({
        success: true,
        warning: "User not found or created for session",
      });
    }

    if (!ObjectId.isValid(contestId))
      return res.status(400).json({ error: "Invalid contest id" });
    const contest = await Contests.findOne({ _id: new ObjectId(contestId) });
    if (!contest) return res.status(404).json({ error: "Contest not found" });

    const existing = await Registrations.findOne({
      user: new ObjectId(user._id),
      contest: new ObjectId(contestId),
    });
    if (existing) {
      return res.json({ success: true, message: "Already registered" });
    }

    const reg = {
      user: new ObjectId(user._id),
      contest: new ObjectId(contestId),
      paymentStatus: "completed",
      submissionStatus: "pending",
      registeredAt: new Date(),
      stripeSessionId: sessionId,
    };

    await Registrations.insertOne(reg);
    await Contests.updateOne(
      { _id: new ObjectId(contestId) },
      { $inc: { participantsCount: 1 } }
    );
    await Users.updateOne(
      { _id: new ObjectId(user._id) },
      { $inc: { participatedCount: 1 } }
    );

    console.log("✅ Payment success complete for user", user.email);
    return res.json({ success: true, registration: reg });
  } catch (err) {
    console.error("❌ Stripe error:", err);
    res.status(400).json({ error: err.message });
  }
});

app.post(
  "/webhook",
  express.raw({ type: "application/json" }),
  async (req, res) => {
    const sig = req.headers["stripe-signature"];
    const webhookSecret = process.env.STRIPE_WEBHOOK_SECRET;

    let event;
    try {
      if (webhookSecret) {
        event = stripe.webhooks.constructEvent(req.body, sig, webhookSecret);
      } else {
        event = JSON.parse(req.body.toString());
      }
    } catch (err) {
      console.error("❌ Webhook signature verification failed:", err.message);
      return res.status(400).send(`Webhook Error: ${err.message}`);
    }

    if (event.type === "checkout.session.completed") {
      const session = event.data.object;
      const contestId = session.metadata?.contestId;
      const customerEmail =
        session.customer_email || session.customer_details?.email;

      if (!contestId) {
        return res
          .status(200)
          .json({ received: true, warning: "missing contestId" });
      }

      try {
        let user = null;
        const metaUserId =
          session.metadata?.userId || session.metadata?.user_id || "";
        if (metaUserId && ObjectId.isValid(metaUserId)) {
          user = await Users.findOne({ _id: new ObjectId(metaUserId) });
        }
        if (!user && customerEmail) {
          user = await Users.findOne({ email: customerEmail.toLowerCase() });
        }
        if (!user && customerEmail) {
          const guest = {
            name:
              session.customer_details?.name ||
              session.customer_details?.email?.split("@")[0] ||
              "Guest",
            email: customerEmail.toLowerCase(),
            photoURL: "https://via.placeholder.com/48",
            role: "user",
            participatedCount: 0,
            wonCount: 0,
            createdAt: new Date(),
          };
          const r = await Users.insertOne(guest);
          guest._id = r.insertedId;
          user = guest;
        }

        if (!user || !ObjectId.isValid(contestId)) {
          return res
            .status(200)
            .json({ received: true, warning: "invalid data" });
        }

        const contest = await Contests.findOne({
          _id: new ObjectId(contestId),
        });
        if (!contest) {
          return res
            .status(200)
            .json({ received: true, warning: "contest not found" });
        }

        const existing = await Registrations.findOne({
          user: new ObjectId(user._id),
          contest: new ObjectId(contestId),
        });
        if (existing) {
          return res
            .status(200)
            .json({ received: true, message: "already registered" });
        }

        const reg = {
          user: new ObjectId(user._id),
          contest: new ObjectId(contestId),
          paymentStatus: "completed",
          submissionStatus: "pending",
          registeredAt: new Date(),
          stripeSessionId: session.id,
        };

        await Registrations.insertOne(reg);
        await Contests.updateOne(
          { _id: new ObjectId(contestId) },
          { $inc: { participantsCount: 1 } }
        );
        await Users.updateOne(
          { _id: new ObjectId(user._id) },
          { $inc: { participatedCount: 1 } }
        );

        console.log(`✅ Webhook: registered user ${user.email}`);
        return res.status(200).json({ received: true });
      } catch (err) {
        console.error("❌ Webhook processing error:", err);
        return res.status(500).json({ error: "Webhook processing failed" });
      }
    }

    res.status(200).json({ received: true });
  }
);

// ==================== CREATOR REQUEST ROUTES ====================
app.get("/api/creator-requests/my-status", authMiddleware, async (req, res) => {
  try {
    const request = await db.collection("creator_requests").findOne(
      {
        userId: new ObjectId(req.user._id),
      },
      { sort: { createdAt: -1 } }
    );
    res.json({ request });
  } catch (error) {
    console.error("❌ Error fetching request status:", error);
    res.status(500).json({ error: "Failed to fetch status" });
  }
});

app.post("/api/creator-requests", authMiddleware, async (req, res) => {
  try {
    if (req.user.role === "creator" || req.user.role === "admin") {
      return res.status(400).json({ error: "You are already a creator" });
    }

    const existingRequest = await db.collection("creator_requests").findOne({
      userId: new ObjectId(req.user._id),
      status: "pending",
    });

    if (existingRequest) {
      return res
        .status(400)
        .json({ error: "You already have a pending request" });
    }

    const request = {
      userId: new ObjectId(req.user._id),
      userName: req.user.name,
      userEmail: req.user.email,
      userPhoto: req.user.photoURL,
      status: "pending",
      createdAt: new Date(),
    };

    const result = await db.collection("creator_requests").insertOne(request);
    res.json({
      success: true,
      message: "Creator request submitted successfully",
      request: { ...request, _id: result.insertedId },
    });
  } catch (error) {
    console.error("❌ Error creating creator request:", error);
    res.status(500).json({ error: "Failed to submit request" });
  }
});

app.get(
  "/api/admin/creator-requests",
  authMiddleware,
  requireRole("admin"),
  async (req, res) => {
    try {
      const requests = await db
        .collection("creator_requests")
        .find({})
        .sort({ createdAt: -1 })
        .toArray();
      res.json({ requests });
    } catch (error) {
      console.error("❌ Error fetching creator requests:", error);
      res.status(500).json({ error: "Failed to fetch requests" });
    }
  }
);

app.put(
  "/api/admin/creator-requests/:id",
  authMiddleware,
  requireRole("admin"),
  async (req, res) => {
    try {
      const { id } = req.params;
      const { status } = req.body;

      if (!ObjectId.isValid(id)) {
        return res.status(400).json({ error: "Invalid request ID" });
      }

      if (!["approved", "rejected"].includes(status)) {
        return res.status(400).json({ error: "Invalid status" });
      }

      const request = await db
        .collection("creator_requests")
        .findOne({ _id: new ObjectId(id) });

      if (!request) {
        return res.status(404).json({ error: "Request not found" });
      }

      await db.collection("creator_requests").updateOne(
        { _id: new ObjectId(id) },
        {
          $set: {
            status,
            processedAt: new Date(),
            processedBy: req.user._id,
          },
        }
      );

      if (status === "approved") {
        await Users.updateOne(
          { _id: request.userId },
          { $set: { role: "creator" } }
        );
      }

      res.json({ success: true, message: `Request ${status} successfully` });
    } catch (error) {
      console.error("❌ Error processing creator request:", error);
      res.status(500).json({ error: "Failed to process request" });
    }
  }
);

// ==================== WINNERS & LEADERBOARD ====================
app.get("/api/winners", async (req, res) => {
  const winners = await Submissions.aggregate([
    { $match: { isWinner: true } },
    {
      $lookup: {
        from: "users",
        localField: "user",
        foreignField: "_id",
        as: "user",
      },
    },
    { $unwind: "$user" },
    {
      $lookup: {
        from: "contests",
        localField: "contest",
        foreignField: "_id",
        as: "contest",
      },
    },
    { $unwind: "$contest" },
    {
      $project: {
        _id: 1,
        name: "$user.name",
        photoURL: "$user.photoURL",
        contestName: "$contest.name",
        prizeMoney: "$contest.prizeMoney",
        wonAt: { $ifNull: ["$updatedAt", "$submittedAt"] },
      },
    },
    { $sort: { wonAt: -1 } },
    { $limit: 50 },
  ]).toArray();
  res.json({ winners });
});

app.get("/api/leaderboard", async (req, res) => {
  try {
    const leaderboard = await Users.aggregate([
      { $match: { wonCount: { $gt: 0 } } },
      {
        $lookup: {
          from: "submissions",
          let: { userId: "$_id" },
          pipeline: [
            {
              $match: {
                $expr: {
                  $and: [
                    { $eq: ["$user", "$$userId"] },
                    { $eq: ["$isWinner", true] },
                  ],
                },
              },
            },
            {
              $lookup: {
                from: "contests",
                localField: "contest",
                foreignField: "_id",
                as: "contestInfo",
              },
            },
            { $unwind: "$contestInfo" },
            {
              $group: {
                _id: null,
                totalPrizes: { $sum: "$contestInfo.prizeMoney" },
              },
            },
          ],
          as: "winnings",
        },
      },
      {
        $project: {
          _id: 1,
          name: 1,
          email: 1,
          photoURL: 1,
          wins: "$wonCount",
          totalPrizes: {
            $ifNull: [{ $arrayElemAt: ["$winnings.totalPrizes", 0] }, 0],
          },
        },
      },
      { $sort: { wins: -1, totalPrizes: -1 } },
    ]).toArray();

    res.json({ leaderboard });
  } catch (error) {
    console.error("❌ Error fetching leaderboard:", error);
    res.status(500).json({ error: "Failed to fetch leaderboard" });
  }
});

// ==================== ADMIN ROUTES ====================
app.get(
  "/api/admin/users",
  authMiddleware,
  requireRole("admin"),
  async (req, res) => {
    const users = await Users.find(
      {},
      { projection: { password: 0 } }
    ).toArray();
    res.json({ users });
  }
);

app.put(
  "/api/admin/users/:id/role",
  authMiddleware,
  requireRole("admin"),
  async (req, res) => {
    const { id } = req.params;
    const { role } = req.body;
    if (!ObjectId.isValid(id))
      return res.status(400).json({ error: "Invalid id" });
    if (!["user", "creator", "admin"].includes(role))
      return res.status(400).json({ error: "Invalid role" });
    await Users.updateOne({ _id: new ObjectId(id) }, { $set: { role } });
    res.json({ success: true });
  }
);

app.put(
  "/api/admin/contests/:id/status",
  authMiddleware,
  requireRole("admin"),
  async (req, res) => {
    const { id } = req.params;
    const { status } = req.body;
    if (!ObjectId.isValid(id))
      return res.status(400).json({ error: "Invalid id" });
    if (!["pending", "confirmed", "rejected"].includes(status))
      return res.status(400).json({ error: "Invalid status" });
    await Contests.updateOne({ _id: new ObjectId(id) }, { $set: { status } });
    res.json({ success: true });
  }
);

app.get(
  "/api/admin/contests",
  authMiddleware,
  requireRole("admin"),
  async (req, res) => {
    const contests = await Contests.find({}).sort({ createdAt: -1 }).toArray();
    res.json({ contests });
  }
);

app.get("/api/contests", async (req, res) => {
  try {
    const { page = 1, limit = 20, status, type, creator } = req.query;
    const skip = (parseInt(page) - 1) * parseInt(limit);
    const filter = {};
    if (status) filter.status = status;
    if (type) filter.type = type;
    if (creator && ObjectId.isValid(creator))
      filter.creator = new ObjectId(creator);

    const contests = await Contests.find(filter)
      .sort({ createdAt: -1 })
      .skip(skip)
      .limit(parseInt(limit))
      .toArray();
    const total = await Contests.countDocuments(filter);
    res.json({
      contests,
      total,
      page: parseInt(page),
      pages: Math.ceil(total / parseInt(limit)),
    });
  } catch (error) {
    console.error("❌ Error:", error);
    res.status(500).json({ error: "Server error" });
  }
});

// ==================== STATS ROUTE ====================
app.get("/api/stats", authMiddleware, async (req, res) => {
  try {
    const userId = new ObjectId(req.user._id);
    const role = req.user.role;

    let stats = {
      activeContests: 0,
      totalWins: 0,
      totalWinnings: 0,
      totalContests: 0,
      totalParticipants: 0,
      totalSubmissions: 0,
      totalPrizes: 0,
      pendingContests: 0,
      rejectedContests: 0,
      totalUsers: 0,
    };

    if (role === "user") {
      stats.activeContests = await Registrations.countDocuments({
        user: userId,
      });
      stats.totalWins = req.user.wonCount || 0;
      const submissions = await Submissions.find({
        user: userId,
        isWinner: true,
      }).toArray();
      stats.totalWinnings = submissions.reduce(
        (sum, s) => sum + (s.prizeMoney || 0),
        0
      );
    }

    if (role === "creator") {
      stats.totalContests = await Contests.countDocuments({ creator: userId });
      stats.pendingContests = await Contests.countDocuments({
        creator: userId,
        status: "pending",
      });
      stats.rejectedContests = await Contests.countDocuments({
        creator: userId,
        status: "rejected",
      });
      const createdContests = await Contests.find({
        creator: userId,
      }).toArray();
      stats.totalParticipants = createdContests.reduce(
        (sum, c) => sum + (c.participantsCount || 0),
        0
      );
      stats.totalSubmissions = createdContests.reduce(
        (sum, c) => sum + (c.submissionsCount || 0),
        0
      );
      stats.totalPrizes = createdContests.reduce(
        (sum, c) => sum + (c.prizeMoney || 0),
        0
      );
    }

    if (role === "admin") {
      stats.totalUsers = await Users.countDocuments();
      stats.totalContests = await Contests.countDocuments();
      stats.totalParticipants = await Registrations.countDocuments();
      stats.totalSubmissions = await Submissions.countDocuments();
      const allContests = await Contests.find({}).toArray();
      stats.totalPrizes = allContests.reduce(
        (sum, c) => sum + (c.prizeMoney || 0),
        0
      );
    }

    res.json(stats);
  } catch {
    res.status(500).json({ error: "Failed to load stats" });
  }
});

// ==================== CENTRAL ERROR HANDLER ====================
app.use((err, req, res, next) => {
  console.error("Unhandled error:", err && (err.stack || err.message || err));
  if (res.headersSent) return next(err);
  res
    .status(err && err.status ? err.status : 500)
    .json({ error: "Server error" });
});

module.exports = app;
