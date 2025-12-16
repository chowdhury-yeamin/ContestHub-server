const express = require("express");
const cors = require("cors");
require("dotenv").config();
const { MongoClient, ObjectId } = require("mongodb");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const multer = require("multer");
const fs = require("fs-extra");
const path = require("path");
const { randomUUID } = require("crypto");
const admin = require("firebase-admin");

// Firebase admin init
let bucket = null;
try {
  if (process.env.FB_SERVICE_KEY) {
    const svc = JSON.parse(
      Buffer.from(process.env.FB_SERVICE_KEY, "base64").toString("utf8")
    );
    admin.initializeApp({
      credential: admin.credential.cert(svc),
      storageBucket: process.env.FB_STORAGE_BUCKET || undefined,
    });
    console.log("✅ Firebase Admin initialized from FB_SERVICE_KEY");
  } else if (process.env.GOOGLE_APPLICATION_CREDENTIALS) {
    admin.initializeApp({
      credential: admin.credential.applicationDefault(),
      storageBucket: process.env.FB_STORAGE_BUCKET || undefined,
    });
    console.log(
      "✅ Firebase Admin initialized from GOOGLE_APPLICATION_CREDENTIALS"
    );
  } else {
    admin.initializeApp();
    console.log("✅ Firebase Admin initialized (default)");
  }
  try {
    bucket = admin.storage().bucket(process.env.FB_STORAGE_BUCKET);
  } catch (err) {
    // Bucket may be undefined
    console.warn("⚠️ Firebase Storage bucket not available:", err.message);
  }
} catch (error) {
  console.error("❌ Firebase Admin error:", error.message);
}

// Config
const PORT = process.env.PORT || 5000;
const MONGO_URI = process.env.MONGO_URI;
const DB_NAME = process.env.DB_NAME || "contesthub";
const JWT_SECRET = process.env.JWT_SECRET || "dev_jwt_secret";


// App
const app = express();
app.use(cors());
app.use(express.json());

// Multer memory storage
const upload = multer({
  storage: multer.memoryStorage(),
  limits: { fileSize: 10 * 1024 * 1024 },
});
const stripe = require("stripe")(process.env.STRIPE_SECRET);

// Mongo client
const client = new MongoClient(MONGO_URI);
let db, Users, Contests, Registrations, Submissions;

async function connectDB() {
  try {
    await client.connect();
    db = client.db(DB_NAME);
    Users = db.collection("users");
    Contests = db.collection("contests");
    Registrations = db.collection("registrations");
    Submissions = db.collection("submissions");

    await Users.createIndex({ email: 1 }, { unique: true });
    await Contests.createIndex({ creator: 1 });
    await Registrations.createIndex({ user: 1, contest: 1 }, { unique: true });
    await Submissions.createIndex({ contest: 1, user: 1 });
    console.log("✅ MongoDB connected");
  } catch (error) {
    console.error("❌ MongoDB error:", error);
    process.exit(1);
  }
}

process.on("SIGINT", async () => {
  await client.close();
  process.exit(0);
});

// Helpers
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

// Auth routes
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
  if (!idToken) return res.status(400).json({ error: "Missing idToken" });

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

// Contests
app.post(
  "/api/contests",
  authMiddleware,
  requireRole("creator"),
  async (req, res) => {
    try {
      const {
        name,
        description,
        image,
        type,
        prizeMoney,
        deadline,
        entryFee,
        participantsLimit,
        tags,
        taskInstruction,
      } = req.body;

      if (!name || !description || !deadline) {
        return res.status(400).json({ error: "Required fields missing" });
      }

      const slug =
        name
          .toLowerCase()
          .replace(/[^a-z0-9]+/g, "-")
          .replace(/^-+|-+$/g, "") +
        "-" +
        Date.now();

      const creatorId =
        req.user._id instanceof ObjectId
          ? req.user._id
          : new ObjectId(req.user._id);

      const contest = {
        name,
        slug,
        description,
        image: image || "https://via.placeholder.com/400x300",
        type: type || "general",
        contestType: type || "general",
        prizeMoney: Number(prizeMoney) || 0,
        deadline: new Date(deadline),
        entryFee: Number(entryFee) || 0,
        participantsLimit: participantsLimit ? Number(participantsLimit) : null,
        tags: Array.isArray(tags) ? tags : [],
        taskInstruction: taskInstruction || "",
        creator: creatorId,
        creatorName: req.user.name,
        creatorEmail: req.user.email,
        status: "pending",
        participantsCount: 0,
        submissionsCount: 0,
        winner: null,
        createdAt: new Date(),
        updatedAt: new Date(),
      };

      const result = await Contests.insertOne(contest);
      const createdContest = await Contests.findOne({ _id: result.insertedId });

      res.status(201).json({
        success: true,
        contest: createdContest,
      });
    } catch (err) {
      console.error("❌ Contest creation error:", err.message);
      res.status(500).json({
        error: err.message,
        details: "Failed to create contest",
      });
    }
  }
);

// Update contest
app.put("/api/contests/:id", authMiddleware, async (req, res) => {
  try {
    const { id } = req.params;

    if (!ObjectId.isValid(id)) {
      return res.status(400).json({ error: "Invalid contest ID" });
    }

    const contest = await Contests.findOne({ _id: new ObjectId(id) });

    if (!contest) {
      return res.status(404).json({ error: "Contest not found" });
    }

    if (
      req.user.role !== "admin" &&
      contest.creator.toString() !== req.user._id.toString()
    ) {
      return res.status(403).json({ error: "Forbidden" });
    }

    const {
      name,
      description,
      image,
      type,
      prizeMoney,
      deadline,
      entryFee,
      participantsLimit,
      tags,
      taskInstruction,
    } = req.body;

    const updates = {};
    if (name) updates.name = name;
    if (description) updates.description = description;
    if (image) updates.image = image;
    if (type) {
      updates.type = type;
      updates.contestType = type;
    }
    if (prizeMoney !== undefined) updates.prizeMoney = Number(prizeMoney);
    if (deadline) updates.deadline = new Date(deadline);
    if (entryFee !== undefined) updates.entryFee = Number(entryFee);
    if (participantsLimit !== undefined) {
      updates.participantsLimit = participantsLimit
        ? Number(participantsLimit)
        : null;
    }
    if (tags) updates.tags = Array.isArray(tags) ? tags : [];
    if (taskInstruction !== undefined)
      updates.taskInstruction = taskInstruction;
    updates.updatedAt = new Date();

    await Contests.updateOne({ _id: new ObjectId(id) }, { $set: updates });

    const updatedContest = await Contests.findOne({ _id: new ObjectId(id) });
    res.json({ success: true, contest: updatedContest });
  } catch (error) {
    console.error("❌ Error updating contest:", error);
    res.status(500).json({ error: "Failed to update contest" });
  }
});

// Delete contest
app.delete("/api/contests/:id", authMiddleware, async (req, res) => {
  try {
    const { id } = req.params;

    console.log("📍 DELETE request for contest ID:", id);

    if (!ObjectId.isValid(id)) {
      console.log("❌ Invalid ObjectId format");
      return res.status(400).json({ error: "Invalid contest ID" });
    }

    const contest = await Contests.findOne({ _id: new ObjectId(id) });

    if (!contest) {
      console.log("❌ Contest not found");
      return res.status(404).json({ error: "Contest not found" });
    }

    if (
      req.user.role !== "admin" &&
      contest.creator.toString() !== req.user._id.toString()
    ) {
      console.log("❌ Unauthorized delete attempt");
      return res
        .status(403)
        .json({ error: "Forbidden - You can only delete your own contests" });
    }

    if (contest.status !== "pending" && req.user.role !== "admin") {
      return res.status(400).json({
        error: "Cannot delete confirmed or rejected contests",
      });
    }

    console.log("✅ Deleting contest:", contest.name);

    await Registrations.deleteMany({ contest: new ObjectId(id) });

    const submissions = await Submissions.find({
      contest: new ObjectId(id),
    }).toArray();
    for (const submission of submissions) {
      if (submission.filePath && bucket) {
        try {
          await bucket.file(submission.filePath).delete();
          console.log("🗑️ Deleted storage file:", submission.filePath);
        } catch (err) {
          console.warn(
            "⚠️ Error deleting storage file:",
            submission.filePath,
            err.message
          );
        }
      }
    }
    await Submissions.deleteMany({ contest: new ObjectId(id) });

    await Contests.deleteOne({ _id: new ObjectId(id) });

    console.log("✅ Contest deleted successfully");
    res.json({ success: true, message: "Contest deleted successfully" });
  } catch (error) {
    console.error("❌ Error deleting contest:", error);
    res.status(500).json({ error: "Failed to delete contest" });
  }
});

app.get(
  "/api/contests/creator/my-contests",
  authMiddleware,
  requireRole("creator"),
  async (req, res) => {
    try {
      const contests = await Contests.find({ creator: req.user._id })
        .sort({ createdAt: -1 })
        .toArray();
      res.json({ contests });
    } catch (error) {
      res.status(500).json({ error: "Failed to fetch contests" });
    }
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
  } catch {
    res.status(500).json({ error: "Server error" });
  }
});

app.get("/api/contests/:id", async (req, res) => {
  try {
    const { id } = req.params;

    console.log("📍 Fetching contest with ID:", id);

    if (!ObjectId.isValid(id)) {
      console.log("❌ Invalid ObjectId format");
      return res.status(400).json({ error: "Invalid contest ID" });
    }

    const contest = await Contests.findOne({ _id: new ObjectId(id) });

    if (!contest) {
      console.log("❌ Contest not found");
      return res.status(404).json({ error: "Contest not found" });
    }

    console.log("✅ Contest found:", contest.name);
    res.json({ contest });
  } catch (error) {
    console.error("❌ Error fetching contest:", error);
    res.status(500).json({ error: "Server error" });
  }
});

// Payment
app.post("/api/create-checkout-session", async (req, res) => {
  try {
    const { contestName, contestId, cost, senderEmail, senderId } = req.body;

    if (!contestName || !contestId || !cost || !senderEmail) {
      return res.status(400).json({ error: "Missing payment fields" });
    }

    const amount = Number(cost) * 100;

    if (!Number.isInteger(amount) || amount <= 0) {
      return res.status(400).json({ error: "Invalid amount" });
    }

    // Site domain
    const siteDomain =
      process.env.SITE_DOMAIN || req.headers.origin || `http://localhost:5173`;

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
      // Include session id
      success_url: `${siteDomain}/dashboard/payment-success?session_id={CHECKOUT_SESSION_ID}`,
      cancel_url: `${siteDomain}/dashboard/payment-canceled`,
    });

    res.json({ url: session.url });
  } catch (err) {
    console.error("❌ Stripe error:", err);
    res.status(400).json({ error: err.message });
  }
});

app.patch("/payment-success", async (req, res) => {
  try {
    const sessionId = req.query.session_id;
    console.log("📍 /payment-success called with sessionId:", sessionId);
    if (!sessionId)
      return res.status(400).json({ error: "Missing session_id" });

    // Retrieve Stripe session
    console.log("🔍 Retrieving Stripe session:", sessionId);
    const session = await stripe.checkout.sessions.retrieve(sessionId);
    console.log("✅ Stripe session retrieved:", {
      id: session.id,
      payment_status: session.payment_status,
    });
    if (!session) return res.status(404).json({ error: "Session not found" });

    const contestId = session.metadata?.contestId;
    const customerEmail =
      session.customer_email || session.customer_details?.email;

    console.log(
      "📊 Session data: contestId=",
      contestId,
      "email=",
      customerEmail
    );

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
      // Create guest user
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
        createdAt: new Date(),
      };
      const r = await Users.insertOne(guest);
      guest._id = r.insertedId;
      user = guest;
      console.log("ℹ️ Created guest user for payment email", customerEmail);
    }
    if (!user) {
      console.warn(
        "⚠️ Payment succeeded but user not found and email missing:",
        customerEmail
      );
      return res.json({
        success: true,
        warning: "User not found or created for session",
      });
    }

    // Validate contest
    if (!ObjectId.isValid(contestId))
      return res.status(400).json({ error: "Invalid contest id" });
    const contest = await Contests.findOne({ _id: new ObjectId(contestId) });
    if (!contest) return res.status(404).json({ error: "Contest not found" });

    // Prevent duplicates
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
    console.log("✅ Registration inserted:", reg._id);

    await Contests.updateOne(
      { _id: new ObjectId(contestId) },
      { $inc: { participantsCount: 1 } }
    );
    console.log("✅ Contest count updated");

    await Users.updateOne(
      { _id: new ObjectId(user._id) },
      { $inc: { participatedCount: 1 } }
    );
    console.log("✅ User count updated");

    console.log("✅ Payment success complete for user", user.email);
    return res.json({ success: true, registration: reg });
  } catch (err) {
    console.error("❌ Stripe error:", err);
    res.status(400).json({ error: err.message });
  }
});

// Stripe webhook

app.post(
  "/webhook",
  express.raw({ type: "application/json" }),
  async (req, res) => {
    const sig = req.headers["stripe-signature"];
    const webhookSecret = process.env.STRIPE_WEBHOOK_SECRET;

    if (!webhookSecret) {
      console.warn(
        "⚠️ STRIPE_WEBHOOK_SECRET not set - webhook signature won't be verified"
      );
    }

    let event;
    try {
      if (webhookSecret) {
        event = stripe.webhooks.constructEvent(req.body, sig, webhookSecret);
      } else {
        // Fallback JSON parse
        event = JSON.parse(req.body.toString());
      }
    } catch (err) {
      console.error("❌ Webhook signature verification failed:", err.message);
      return res.status(400).send(`Webhook Error: ${err.message}`);
    }

    // Handle checkout.completed
    if (event.type === "checkout.session.completed") {
      const session = event.data.object;

      const contestId = session.metadata?.contestId;
      const customerEmail =
        session.customer_email || session.customer_details?.email;

      if (!contestId) {
        console.warn("Webhook session missing contestId", session.id);
        return res
          .status(200)
          .json({ received: true, warning: "missing contestId" });
      }

      try {
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
            createdAt: new Date(),
          };
          const r = await Users.insertOne(guest);
          guest._id = r.insertedId;
          user = guest;
          console.log("ℹ️ Webhook: created guest user for", customerEmail);
        }

        if (!user) {
          console.warn(
            "⚠️ Webhook: user not found and no customer email",
            session.id
          );
          return res
            .status(200)
            .json({ received: true, warning: "user not found" });
        }

        if (!ObjectId.isValid(contestId)) {
          console.warn("⚠️ Webhook: invalid contest id", contestId);
          return res
            .status(200)
            .json({ received: true, warning: "invalid contest id" });
        }

        const contest = await Contests.findOne({
          _id: new ObjectId(contestId),
        });
        if (!contest) {
          console.warn("⚠️ Webhook: contest not found", contestId);
          return res
            .status(200)
            .json({ received: true, warning: "contest not found" });
        }

        // Prevent duplicates
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

        console.log(
          `✅ Webhook: registered user ${user.email} for contest ${contest.name}`
        );
        return res.status(200).json({ received: true });
      } catch (err) {
        console.error("❌ Webhook processing error:", err);
        return res.status(500).json({ error: "Webhook processing failed" });
      }
    }

    // Other events
    res.status(200).json({ received: true });
  }
);

// Admin requests
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

// Registrations
app.post("/api/contests/:id/register", authMiddleware, async (req, res) => {
  const { id } = req.params;
  if (!ObjectId.isValid(id))
    return res.status(400).json({ error: "Invalid id" });

  try {
    const contest = await Contests.findOne({ _id: new ObjectId(id) });
    if (!contest) return res.status(404).json({ error: "Contest not found" });
    if (contest.status !== "confirmed")
      return res.status(400).json({ error: "Contest not available" });

    const reg = {
      user: new ObjectId(req.user._id),
      contest: new ObjectId(id),
      paymentStatus: "completed",
      submissionStatus: "pending",
      registeredAt: new Date(),
    };

    await Registrations.insertOne(reg);
    await Contests.updateOne(
      { _id: new ObjectId(id) },
      { $inc: { participantsCount: 1 } }
    );
    await Users.updateOne(
      { _id: new ObjectId(req.user._id) },
      { $inc: { participatedCount: 1 } }
    );
    res.json({ success: true, registration: reg });
  } catch (err) {
    if (err.code === 11000)
      return res.status(400).json({ error: "Already registered" });
    res.status(500).json({ error: "Server error" });
  }
});

app.get("/api/users/me/registrations", authMiddleware, async (req, res) => {
  const regs = await Registrations.find({
    user: new ObjectId(req.user._id),
  }).toArray();
  const contests = await Promise.all(
    regs.map(async (r) => ({
      ...r,
      contest: await Contests.findOne({ _id: r.contest }),
    }))
  );
  res.json({ registrations: contests });
});

app.get("/api/users/me/wins", authMiddleware, async (req, res) => {
  const wins = await Submissions.find({
    user: new ObjectId(req.user._id),
    isWinner: true,
  }).toArray();
  const contests = await Promise.all(
    wins.map(async (w) => ({
      ...w,
      contest: await Contests.findOne({ _id: w.contest }),
      wonAt: w.updatedAt || w.createdAt,
    }))
  );
  res.json({ wins: contests });
});

// Submissions
app.post(
  "/api/contests/:id/submit",
  authMiddleware,
  upload.single("file"),
  async (req, res) => {
    const { id } = req.params;
    if (!ObjectId.isValid(id)) {
      return res.status(400).json({ error: "Invalid id" });
    }

    try {
      const contest = await Contests.findOne({ _id: new ObjectId(id) });
      if (!contest) {
        return res.status(404).json({ error: "Contest not found" });
      }

      const registration = await Registrations.findOne({
        user: new ObjectId(req.user._id),
        contest: new ObjectId(id),
      });
      if (!registration) {
        return res.status(400).json({ error: "Must register first" });
      }

      // Upload to storage
      let filePath = null;
      let fileOriginalName = null;
      if (req.file) {
        if (!bucket)
          return res.status(500).json({ error: "Storage not configured" });
        const filename = `uploads/${randomUUID()}${path.extname(
          req.file.originalname
        )}`;
        try {
          await bucket.file(filename).save(req.file.buffer, {
            metadata: { contentType: req.file.mimetype },
          });
          filePath = filename;
          fileOriginalName = req.file.originalname;
          console.log("✅ Uploaded file to storage:", filename);
        } catch (err) {
          console.error("❌ Storage upload failed:", err.message);
          return res.status(500).json({ error: "Failed to upload file" });
        }
      }

      const submission = {
        contest: new ObjectId(id),
        user: new ObjectId(req.user._id),
        userName: req.user.name,
        submission: req.body.submission || (filePath ? filePath : ""),
        filePath: filePath,
        fileOriginalName: fileOriginalName,
        submittedAt: new Date(),
        isWinner: false,
      };

      const result = await Submissions.insertOne(submission);
      await Contests.updateOne(
        { _id: new ObjectId(id) },
        { $inc: { submissionsCount: 1 } }
      );
      await Registrations.updateOne(
        { user: new ObjectId(req.user._id), contest: new ObjectId(id) },
        { $set: { submissionStatus: "submitted" } }
      );
      res.json({
        submission: await Submissions.findOne({ _id: result.insertedId }),
      });
    } catch (error) {
      res.status(500).json({ error: "Server error" });
    }
  }
);

app.get("/api/contests/:id/submissions", authMiddleware, async (req, res) => {
  const { id } = req.params;

  if (!ObjectId.isValid(id))
    return res.status(400).json({ error: "Invalid id" });

  const contest = await Contests.findOne({ _id: new ObjectId(id) });
  if (!contest) return res.status(404).json({ error: "Contest not found" });

  if (
    req.user.role !== "admin" &&
    contest.creator.toString() !== req.user._id.toString()
  )
    return res.status(403).json({ error: "Forbidden" });

  const submissions = await Submissions.aggregate([
    { $match: { contest: new ObjectId(id) } },
    {
      $lookup: {
        from: "users",
        localField: "user",
        foreignField: "_id",
        as: "participant",
      },
    },
    { $unwind: "$participant" },
    {
      $project: {
        _id: 1,
        submission: 1,
        submittedAt: 1,
        isWinner: 1,
        participant: { _id: 1, name: 1, email: 1, photoURL: 1 },
      },
    },
  ]).toArray();

  res.json({ submissions });
});

// Creator submissions
app.get(
  "/api/creator/all-submissions",
  authMiddleware,
  requireRole("creator"),
  async (req, res) => {
    try {
      const creatorContests = await Contests.find({
        creator: new ObjectId(req.user._id),
      }).toArray();

      const contestIds = creatorContests.map((c) => c._id);

      if (contestIds.length === 0) {
        return res.json({ submissions: [] });
      }

      const submissions = await Submissions.aggregate([
        { $match: { contest: { $in: contestIds } } },
        {
          $lookup: {
            from: "users",
            localField: "user",
            foreignField: "_id",
            as: "participant",
          },
        },
        { $unwind: "$participant" },
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
          $project: {
            _id: 1,
            submission: 1,
            submittedAt: 1,
            isWinner: 1,
            contest: "$contestInfo._id",
            contestName: "$contestInfo.name",
            contestDeadline: "$contestInfo.deadline",
            contestPrizeMoney: "$contestInfo.prizeMoney",
            participant: {
              _id: 1,
              name: 1,
              email: 1,
              photoURL: 1,
            },
          },
        },
        { $sort: { submittedAt: -1 } },
      ]).toArray();

      res.json({ submissions });
    } catch (error) {
      console.error("❌ Error fetching all submissions:", error);
      res.status(500).json({ error: "Failed to fetch submissions" });
    }
  }
);

app.post("/api/submissions/:id/winner", authMiddleware, async (req, res) => {
  const { id } = req.params;
  if (!ObjectId.isValid(id))
    return res.status(400).json({ error: "Invalid id" });

  const sub = await Submissions.findOne({ _id: new ObjectId(id) });
  if (!sub) return res.status(404).json({ error: "Submission not found" });

  const contest = await Contests.findOne({ _id: sub.contest });
  if (!contest) return res.status(404).json({ error: "Contest not found" });
  if (
    req.user.role !== "admin" &&
    contest.creator.toString() !== req.user._id.toString()
  )
    return res.status(403).json({ error: "Forbidden" });

  await Submissions.updateOne(
    { _id: new ObjectId(id) },
    { $set: { isWinner: true, updatedAt: new Date() } }
  );
  await Contests.updateOne(
    { _id: contest._id },
    { $set: { winner: sub.user } }
  );
  await Users.updateOne({ _id: sub.user }, { $inc: { wonCount: 1 } });
  res.json({ success: true });
});

// Winners
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

// Leaderboard
app.get("/api/leaderboard", async (req, res) => {
  try {
    const leaderboard = await Users.aggregate([
      {
        $match: {
          wonCount: { $gt: 0 },
        },
      },
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
      {
        $sort: { wins: -1, totalPrizes: -1 },
      },
    ]).toArray();

    res.json({ leaderboard });
  } catch (error) {
    console.error("❌ Error fetching leaderboard:", error);
    res.status(500).json({ error: "Failed to fetch leaderboard" });
  }
});

// Admin
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

// Stats
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

// Health
app.get("/", (req, res) => res.send("✅ ContestHub API running"));
app.get("/health", (req, res) => res.json({ ok: true, timestamp: new Date() }));

// Start server
connectDB().then(() => {
  app.listen(PORT, () =>
    console.log(`🚀 Server running on http://localhost:${PORT}`)
  );
});
