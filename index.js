const express = require("express");
const cors = require("cors");
require("dotenv").config();
const { MongoClient, ObjectId } = require("mongodb");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const multer = require("multer");
const fs = require("fs-extra");
const path = require("path");
const { v4: uuidv4, parse } = require("uuid");
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
const stripe = require("stripe")(process.env.STRIPE_SECRET);

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

// ---------------- UPDATE CONTEST ----------------
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

// ---------------- DELETE CONTEST ----------------
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
      if (submission.filePath) {
        const filePath = path.join(UPLOADS_DIR, submission.filePath);
        try {
          await fs.remove(filePath);
          console.log("🗑️ Deleted file:", submission.filePath);
        } catch (err) {
          console.error("⚠️ Error deleting file:", err.message);
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

//------------------ Payment -----------------------
app.post("/api/create-checkout-session", async (req, res) => {
  try {
    const { contestName, contestId, cost, senderEmail } = req.body;

    if (!contestName || !contestId || !cost || !senderEmail) {
      return res.status(400).json({ error: "Missing payment fields" });
    }

    const amount = Number(cost) * 100;

    if (!Number.isInteger(amount) || amount <= 0) {
      return res.status(400).json({ error: "Invalid amount" });
    }

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
      metadata: { contestId },
      success_url: `${process.env.SITE_DOMAIN}/dashboard/payment-success`,
      cancel_url: `${process.env.SITE_DOMAIN}/dashboard/payment-canceled`,
    });

    res.json({ url: session.url });
  } catch (err) {
    console.error("❌ Stripe error:", err);
    res.status(400).json({ error: err.message });
  }
});

//------------------ Admin Requests -----------------------
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

// ---------------- GET ALL SUBMISSIONS FOR CREATOR ----------------
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

// ---------------- LEADERBOARD ----------------
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

// ---------------- STATS ----------------
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

// ---------------- HEALTH ----------------
app.get("/", (req, res) => res.send("✅ ContestHub API running"));
app.get("/health", (req, res) => res.json({ ok: true, timestamp: new Date() }));

// Start server
connectDB().then(() => {
  app.listen(PORT, () =>
    console.log(`🚀 Server running on http://localhost:${PORT}`)
  );
});
