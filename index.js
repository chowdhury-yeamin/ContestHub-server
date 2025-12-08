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

// ---------------- CONFIG ----------------
const PORT = process.env.PORT || 5000;
const MONGO_URI = process.env.MONGO_URI;
const DB_NAME = process.env.DB_NAME || "contesthub";
const JWT_SECRET = process.env.JWT_SECRET || "dev_jwt_secret";
const UPLOADS_DIR = path.join(__dirname, "uploads");

fs.ensureDirSync(UPLOADS_DIR);

// ---------------- MONGO CLIENT ----------------
const client = new MongoClient(MONGO_URI);
let db, Users, Contests, Registrations, Submissions;

async function connectDB() {
  await client.connect();
  db = client.db(DB_NAME);
  Users = db.collection("users");
  Contests = db.collection("contests");
  Registrations = db.collection("registrations");
  Submissions = db.collection("submissions");

  await Users.createIndex({ email: 1 }, { unique: true });
  await Contests.createIndex({ slug: 1 }, { unique: true });
  await Registrations.createIndex({ user: 1, contest: 1 }, { unique: true });
  await Submissions.createIndex({ contest: 1, user: 1 });

  console.log("MongoDB connected to", DB_NAME);
}
connectDB().catch((err) => {
  console.error(err);
  process.exit(1);
});

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
const upload = multer({ storage });

// ---------------- HELPERS ----------------
function signToken(user) {
  return jwt.sign(
    { id: user._id.toString(), role: user.role, email: user.email },
    JWT_SECRET,
    { expiresIn: "7d" }
  );
}

async function getUserById(id) {
  if (!ObjectId.isValid(id)) return null;
  return Users.findOne({ _id: new ObjectId(id) });
}

async function authMiddleware(req, res, next) {
  const auth = req.headers.authorization;
  if (!auth || !auth.startsWith("Bearer "))
    return res.status(401).json({ error: "Missing token" });
  try {
    const token = auth.split(" ")[1];
    const payload = jwt.verify(token, JWT_SECRET);
    const user = await getUserById(payload.id);
    if (!user) return res.status(401).json({ error: "User not found" });
    req.user = user;
    next();
  } catch {
    return res.status(401).json({ error: "Invalid token" });
  }
}

function requireRole(role) {
  return (req, res, next) => {
    if (!req.user) return res.status(401).json({ error: "Not authenticated" });
    if (req.user.role !== role && req.user.role !== "admin")
      return res.status(403).json({ error: "Forbidden" });
    next();
  };
}

// ---------------- AUTH ----------------
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
      createdAt: new Date(),
    };
    const result = await Users.insertOne(userDoc);
    const user = await Users.findOne(
      { _id: result.insertedId },
      { projection: { password: 0 } }
    );
    const token = signToken(user);
    return res.json({ user: { ...user, id: user._id }, token });
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
        id: user._id,
        name: user.name,
        email: user.email,
        role: user.role,
      },
      token,
    });
  } catch {
    res.status(500).json({ error: "Server error" });
  }
});

app.get("/api/users/me", authMiddleware, async (req, res) => {
  const { _id, name, email, role, createdAt } = req.user;
  res.json({ user: { id: _id, name, email, role, createdAt } });
});

app.put("/api/users/me", authMiddleware, async (req, res) => {
  const { name, photo, extra } = req.body;
  const updates = {};
  if (name) updates.name = name;
  if (photo) updates.photo = photo;
  if (extra) updates.extra = extra;
  updates.updatedAt = new Date();
  await Users.updateOne({ _id: new ObjectId(req.user._id) }, { $set: updates });
  const user = await Users.findOne(
    { _id: new ObjectId(req.user._id) },
    { projection: { password: 0 } }
  );
  res.json({ user });
});

// ---------------- CONTESTS ----------------
app.post(
  "/api/contests",
  authMiddleware,
  requireRole("creator"),
  async (req, res) => {
    try {
      const {
        title,
        slug,
        description,
        startDate,
        endDate,
        status,
        type,
        prize,
        taskInstructions,
      } = req.body;
      if (!title || !slug)
        return res.status(400).json({ error: "Title and slug required" });
      const contest = {
        title,
        slug,
        description,
        creator: new ObjectId(req.user._id),
        startDate: new Date(startDate),
        endDate: new Date(endDate),
        status: status || "pending",
        type: type || "general",
        prize: prize || 0,
        taskInstructions: taskInstructions || "",
        registrationsCount: 0,
        submissionsCount: 0,
        createdAt: new Date(),
      };
      const result = await Contests.insertOne(contest);
      res.json({ contest: await Contests.findOne({ _id: result.insertedId }) });
    } catch (err) {
      if (err.code === 11000)
        return res.status(400).json({ error: "Slug already exists" });
      res.status(500).json({ error: "Server error" });
    }
  }
);

app.get("/api/contests", async (req, res) => {
  try {
    const { page = 1, limit = 20, status, creator } = req.query;
    const skip = (page - 1) * limit;
    const filter = {};
    if (status) filter.status = status;
    if (creator) filter.creator = new ObjectId(creator);
    const contests = await Contests.find(filter)
      .skip(skip)
      .limit(parseInt(limit))
      .toArray();
    res.json({ contests });
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
    "title",
    "slug",
    "description",
    "startDate",
    "endDate",
    "status",
    "type",
    "prize",
    "taskInstructions",
  ].forEach((k) => {
    if (req.body[k] !== undefined)
      updates[k] = k.includes("Date") ? new Date(req.body[k]) : req.body[k];
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

// ---------------- REGISTRATIONS ----------------
app.post("/api/contests/:id/register", authMiddleware, async (req, res) => {
  const { id } = req.params;
  if (!ObjectId.isValid(id))
    return res.status(400).json({ error: "Invalid id" });
  try {
    const reg = {
      user: new ObjectId(req.user._id),
      contest: new ObjectId(id),
      registeredAt: new Date(),
    };
    await Registrations.insertOne(reg);
    await Contests.updateOne(
      { _id: new ObjectId(id) },
      { $inc: { registrationsCount: 1 } }
    );
    res.json({ success: true, registration: reg });
  } catch (err) {
    if (err.code === 11000)
      return res.status(400).json({ error: "Already registered" });
    res.status(500).json({ error: "Server error" });
  }
});

// User dashboard endpoints
app.get("/api/users/me/registrations", authMiddleware, async (req, res) => {
  const regs = await Registrations.find({
    user: new ObjectId(req.user._id),
  }).toArray();
  const contests = await Promise.all(
    regs.map(async (r) => {
      return await Contests.findOne({ _id: r.contest });
    })
  );
  res.json({ contests });
});

app.get("/api/users/me/wins", authMiddleware, async (req, res) => {
  const wins = await Submissions.find({
    user: new ObjectId(req.user._id),
    isWinner: true,
  }).toArray();
  const contests = await Promise.all(
    wins.map(async (w) => {
      return await Contests.findOne({ _id: w.contest });
    })
  );
  res.json({ contests });
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
    const contest = await Contests.findOne({ _id: new ObjectId(id) });
    if (!contest) {
      if (req.file) await fs.remove(req.file.path);
      return res.status(404).json({ error: "Contest not found" });
    }
    const submission = {
      contest: new ObjectId(id),
      user: new ObjectId(req.user._id),
      title: req.body.title || "untitled",
      description: req.body.description || "",
      filePath: req.file ? req.file.filename : null,
      fileOriginalName: req.file ? req.file.originalname : null,
      createdAt: new Date(),
      isWinner: false,
      score: null,
    };
    const result = await Submissions.insertOne(submission);
    await Contests.updateOne(
      { _id: new ObjectId(id) },
      { $inc: { submissionsCount: 1 } }
    );
    res.json({
      submission: await Submissions.findOne({ _id: result.insertedId }),
    });
  }
);

app.post("/api/submissions/:id/winner", authMiddleware, async (req, res) => {
  const { id } = req.params;
  const { isWinner = true, score = null } = req.body;
  if (!ObjectId.isValid(id))
    return res.status(400).json({ error: "Invalid id" });
  const sub = await Submissions.findOne({ _id: new ObjectId(id) });
  if (!sub) return res.status(404).json({ error: "Submission not found" });
  const contest = await Contests.findOne({ _id: new ObjectId(sub.contest) });
  if (!contest) return res.status(404).json({ error: "Contest not found" });
  if (
    req.user.role !== "admin" &&
    contest.creator.toString() !== req.user._id.toString()
  )
    return res.status(403).json({ error: "Forbidden" });
  await Submissions.updateOne(
    { _id: new ObjectId(id) },
    { $set: { isWinner: isWinner, score, updatedAt: new Date() } }
  );
  res.json({ success: true });
});

// ---------------- LEADERBOARD ----------------
app.get("/api/leaderboard", async (req, res) => {
  const rows = await Submissions.aggregate([
    { $match: { isWinner: true } },
    {
      $group: { _id: "$user", wins: { $sum: 1 }, avgScore: { $avg: "$score" } },
    },
    { $sort: { wins: -1, avgScore: -1 } },
    { $limit: 50 },
    {
      $lookup: {
        from: "users",
        localField: "_id",
        foreignField: "_id",
        as: "user",
      },
    },
    { $unwind: "$user" },
    {
      $project: {
        user: { _id: 1, name: 1, email: 1, role: 1 },
        wins: 1,
        avgScore: 1,
      },
    },
  ]).toArray();
  res.json({ leaderboard: rows });
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

// Approve/reject contest
app.put(
  "/api/admin/contests/:id/status",
  authMiddleware,
  requireRole("admin"),
  async (req, res) => {
    const { id } = req.params;
    const { status } = req.body;
    if (!ObjectId.isValid(id))
      return res.status(400).json({ error: "Invalid id" });
    if (!["pending", "approved", "rejected"].includes(status))
      return res.status(400).json({ error: "Invalid status" });
    await Contests.updateOne({ _id: new ObjectId(id) }, { $set: { status } });
    res.json({ success: true });
  }
);

// ---------------- HEALTH ----------------
app.get("/", (req, res) => res.send("ContestHub backend running"));
app.get("/health", (req, res) => res.json({ ok: true }));

app.listen(PORT, () => console.log(`Server listening on port ${PORT}`));
