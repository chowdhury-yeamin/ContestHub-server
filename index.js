const express = require("express");
const cors = require("cors");
require("dotenv").config();
const { MongoClient, ObjectId } = require("mongodb");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const multer = require("multer");
const fs = require("fs-extra");
const path = require("path");
const { v4: uuidv4 } = require("uuid");
const admin = require("firebase-admin");

// Initialize Firebase Admin
try {
  admin.initializeApp();
  console.log("✅ Firebase Admin initialized");
} catch (error) {
  console.error("❌ Firebase Admin error:", error.message);
}

// ---------------- CONFIG ----------------
const PORT = process.env.PORT || 5000;
const MONGO_URI = process.env.MONGO_URI;
const DB_NAME = process.env.DB_NAME || "contesthub";
const JWT_SECRET = process.env.JWT_SECRET || "dev_jwt_secret";
const UPLOADS_DIR = path.join(__dirname, "uploads");

fs.ensureDirSync(UPLOADS_DIR);

// ---------------- APP ----------------
const app = express();
app.use(cors());
app.use(express.json());
app.use("/uploads", express.static(UPLOADS_DIR));

const storage = multer.diskStorage({
  destination: (req, file, cb) => cb(null, UPLOADS_DIR),
  filename: (req, file, cb) =>
    cb(null, uuidv4() + path.extname(file.originalname)),
});
const upload = multer({ storage, limits: { fileSize: 10 * 1024 * 1024 } });

// ---------------- MONGO CLIENT ----------------
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

// ---------------- HELPERS ----------------
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

// ---------------- AUTH ROUTES ----------------
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
  console.log("📍 Google auth endpoint HIT!");
  const { idToken } = req.body;

  if (!idToken) {
    console.log("❌ No idToken");
    return res.status(400).json({ error: "Missing idToken" });
  }

  try {
    console.log("🔍 Verifying token...");
    const decodedToken = await admin.auth().verifyIdToken(idToken);
    const { uid, email, name, picture } = decodedToken;
    console.log("✅ Verified:", email);

    let user = await Users.findOne({ email: email.toLowerCase() });

    if (!user) {
      console.log("👤 Creating user...");
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
    console.log("✅ Sending response");

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
    console.error("❌ Error:", err.message);
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
  } catch (error) {
    res.status(500).json({ error: "Server error" });
  }
});

// ---------------- CONTESTS ----------------
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
      } = req.body;
      if (!name || !description || !deadline)
        return res.status(400).json({ error: "Required fields missing" });

      const contest = {
        name,
        description,
        image: image || "https://via.placeholder.com/400x300",
        type: type || "general",
        prizeMoney: parseInt(prizeMoney) || 0,
        deadline: new Date(deadline),
        entryFee: parseInt(entryFee) || 0,
        participantsLimit: parseInt(participantsLimit) || null,
        tags: tags || [],
        creator: new ObjectId(req.user._id),
        creatorName: req.user.name,
        status: "pending",
        participantsCount: 0,
        submissionsCount: 0,
        winner: null,
        createdAt: new Date(),
      };

      const result = await Contests.insertOne(contest);
      res.json({ contest: await Contests.findOne({ _id: result.insertedId }) });
    } catch (err) {
      res.status(500).json({ error: "Server error" });
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
  if (!ObjectId.isValid(req.params.id))
    return res.status(400).json({ error: "Invalid id" });
  const contest = await Contests.findOne({ _id: new ObjectId(req.params.id) });
  if (!contest) return res.status(404).json({ error: "Contest not found" });
  res.json({ contest });
});

app.put("/api/contests/:id", authMiddleware, async (req, res) => {
  if (!ObjectId.isValid(req.params.id))
    return res.status(400).json({ error: "Invalid id" });
  const contest = await Contests.findOne({ _id: new ObjectId(req.params.id) });
  if (!contest) return res.status(404).json({ error: "Contest not found" });
  if (
    req.user.role !== "admin" &&
    contest.creator.toString() !== req.user._id.toString()
  )
    return res.status(403).json({ error: "Forbidden" });

  const updates = {};
  [
    "name",
    "description",
    "image",
    "type",
    "prizeMoney",
    "deadline",
    "entryFee",
    "participantsLimit",
    "tags",
  ].forEach((k) => {
    if (req.body[k] !== undefined) {
      if (k === "deadline") updates[k] = new Date(req.body[k]);
      else if (["prizeMoney", "entryFee", "participantsLimit"].includes(k))
        updates[k] = parseInt(req.body[k]);
      else updates[k] = req.body[k];
    }
  });
  updates.updatedAt = new Date();

  await Contests.updateOne(
    { _id: new ObjectId(req.params.id) },
    { $set: updates }
  );
  res.json({
    contest: await Contests.findOne({ _id: new ObjectId(req.params.id) }),
  });
});

app.delete("/api/contests/:id", authMiddleware, async (req, res) => {
  if (!ObjectId.isValid(req.params.id))
    return res.status(400).json({ error: "Invalid id" });
  const contest = await Contests.findOne({ _id: new ObjectId(req.params.id) });
  if (!contest) return res.status(404).json({ error: "Contest not found" });
  if (
    req.user.role !== "admin" &&
    contest.creator.toString() !== req.user._id.toString()
  )
    return res.status(403).json({ error: "Forbidden" });

  await Contests.deleteOne({ _id: new ObjectId(req.params.id) });
  await Registrations.deleteMany({ contest: new ObjectId(req.params.id) });
  const subs = await Submissions.find({
    contest: new ObjectId(req.params.id),
  }).toArray();
  for (const s of subs)
    if (s.filePath) await fs.remove(path.join(UPLOADS_DIR, s.filePath));
  await Submissions.deleteMany({ contest: new ObjectId(req.params.id) });
  res.json({ success: true });
});

app.get(
  "/api/contests/creator/my-contests",
  authMiddleware,
  requireRole("creator"),
  async (req, res) => {
    try {
      const contests = await Contests.find({
        creator: new ObjectId(req.user._id),
      })
        .sort({ createdAt: -1 })
        .toArray();
      res.json({ contests });
    } catch (err) {
      res.status(500).json({ error: "Server error" });
    }
  }
);

// ---------------- REGISTRATIONS ----------------
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

// ---------------- SUBMISSIONS ----------------
app.post(
  "/api/contests/:id/submit",
  authMiddleware,
  upload.single("file"),
  async (req, res) => {
    const { id } = req.params;
    if (!ObjectId.isValid(id)) {
      if (req.file) await fs.remove(req.file.path);
      return res.status(400).json({ error: "Invalid id" });
    }

    try {
      const contest = await Contests.findOne({ _id: new ObjectId(id) });
      if (!contest) {
        if (req.file) await fs.remove(req.file.path);
        return res.status(404).json({ error: "Contest not found" });
      }

      const registration = await Registrations.findOne({
        user: new ObjectId(req.user._id),
        contest: new ObjectId(id),
      });
      if (!registration) {
        if (req.file) await fs.remove(req.file.path);
        return res.status(400).json({ error: "Must register first" });
      }

      const submission = {
        contest: new ObjectId(id),
        user: new ObjectId(req.user._id),
        userName: req.user.name,
        submission: req.body.submission || req.file?.filename || "",
        filePath: req.file ? req.file.filename : null,
        fileOriginalName: req.file ? req.file.originalname : null,
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
      if (req.file) await fs.remove(req.file.path);
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

// ---------------- WINNERS ----------------
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

// ---------------- ADMIN ----------------
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

// ---------------- STATS ENDPOINT ----------------
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

    // ---------- USER ----------
    if (role === "user") {
      stats.activeContests = await Registrations.countDocuments({
        user: userId,
      });
      stats.totalWins = req.user.wonCount || 0;

      // sum winnings
      const submissions = await Submissions.find({
        user: userId,
        isWinner: true,
      }).toArray();

      stats.totalWinnings = submissions.reduce(
        (sum, s) => sum + (s.prizeMoney || 0),
        0
      );
    }

    // ---------- CREATOR ----------
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

    // ---------- ADMIN ----------
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
  } catch (error) {
    res.status(500).json({ error: "Failed to load stats" });
  }
});

// ---------------- HEALTH ----------------
app.get("/", (req, res) => res.send("✅ ContestHub API running"));
app.get("/health", (req, res) => res.json({ ok: true, timestamp: new Date() }));

// Start server
connectDB().then(() => {
  app.listen(PORT, () => {
    console.log(`\n🚀 Server running on http://localhost:${PORT}`);
    console.log(`📡 API: http://localhost:${PORT}/api`);
    console.log(`\n✅ Routes registered:`);
    console.log(`   POST /api/auth/register`);
    console.log(`   POST /api/auth/login`);
    console.log(`   POST /api/auth/google`);
    console.log(`   GET  /api/auth/me`);
  });
});
