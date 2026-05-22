// Initial Express Server Setup
const express = require("express");
const dotenv = require("dotenv");
const cors = require("cors");

dotenv.config();

const app = express();
const PORT = process.env.PORT || 5000;

app.use(cors());
app.use(express.json());

app.get("/", (req, res) => {
  res.send("Server is running fine!");
});

app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});


// MongoDB Connection Setup
const { MongoClient, ServerApiVersion } = require("mongodb");

const uri = process.env.MONGODB_URI;

const client = new MongoClient(uri, {
  serverApi: {
    version: ServerApiVersion.v1,
    strict: true,
    deprecationErrors: true,
  },
});

async function run() {
  try {
    const db = client.db("idea-vault");

    console.log("MongoDB Connected");
  } finally {
  }
}

run().catch(console.dir);


// JWT Authentication Middleware
const jwt = require("jsonwebtoken");

const JWT_SECRET =
  process.env.JWT_SECRET || "your-secret-key-change-in-production";

const verifyToken = async (req, res, next) => {
  const authHeader = req?.headers.authorization;

  if (!authHeader) {
    return res.status(401).json({ message: "Unauthorized" });
  }

  const token = authHeader.split(" ")[1];

  if (!token) {
    return res.status(401).json({ message: "Unauthorized" });
  }

  try {
    const decoded = jwt.verify(token, JWT_SECRET);

    req.user = decoded;

    next();
  } catch (error) {
    return res.status(403).json({ message: "Forbidden" });
  }
};


// User Registration API
const bcryptjs = require("bcryptjs");

const usersCollection = db.collection("users");

app.post("/auth/register", async (req, res) => {
  try {
    const { name, email, password, image } = req.body;

    if (!email || !password || !name) {
      return res.status(400).json({
        message: "Missing required fields",
      });
    }

    const existingUser = await usersCollection.findOne({ email });

    if (existingUser) {
      return res.status(409).json({
        message: "User already exists",
      });
    }

    const hashedPassword = await bcryptjs.hash(password, 10);

    const newUser = {
      name,
      email,
      password: hashedPassword,
      image: image || "",
      createdAt: new Date(),
      updatedAt: new Date(),
    };

    const result = await usersCollection.insertOne(newUser);

    const token = jwt.sign(
      {
        userId: result.insertedId,
        email,
        name,
      },
      JWT_SECRET,
      {
        expiresIn: "7d",
      }
    );

    res.status(201).json({
      message: "User registered successfully",
      token,
    });
  } catch (error) {
    res.status(500).json({
      message: "Registration failed",
    });
  }
});


// User login API
app.post("/auth/login", async (req, res) => {
  try {
    const { email, password } = req.body;

    const user = await usersCollection.findOne({ email });

    if (!user) {
      return res.status(401).json({
        message: "Invalid credentials",
      });
    }

    const isPasswordValid = await bcryptjs.compare(
      password,
      user.password
    );

    if (!isPasswordValid) {
      return res.status(401).json({
        message: "Invalid credentials",
      });
    }

    const token = jwt.sign(
      {
        userId: user._id,
        email: user.email,
        name: user.name,
      },
      JWT_SECRET,
      {
        expiresIn: "7d",
      }
    );

    res.json({
      message: "Login successful",
      token,
    });
  } catch (error) {
    res.status(500).json({
      message: "Login failed",
    });
  }
});


// Google OAuth Authentication
app.post("/auth/google", async (req, res) => {
  try {
    const { name, email, image, googleId } = req.body;

    let user = await usersCollection.findOne({ email });

    if (!user) {
      const newUser = {
        name,
        email,
        password: "",
        image: image || "",
        googleId: googleId || "",
        authMethod: "google",
        createdAt: new Date(),
        updatedAt: new Date(),
      };

      const result = await usersCollection.insertOne(newUser);

      user = {
        ...newUser,
        _id: result.insertedId,
      };
    }

    const token = jwt.sign(
      {
        userId: user._id,
        email: user.email,
        name: user.name,
      },
      JWT_SECRET,
      {
        expiresIn: "7d",
      }
    );

    res.json({
      message: "Google login successful",
      token,
    });
  } catch (error) {
    res.status(500).json({
      message: "Google OAuth failed",
    });
  }
});


// User Profile Management
app.get("/auth/user", verifyToken, async (req, res) => {
  const user = await usersCollection.findOne({
    _id: new ObjectId(req.user.userId),
  });

  res.json({
    user,
  });
});

app.patch("/auth/user", verifyToken, async (req, res) => {
  const { name, image } = req.body;

  await usersCollection.updateOne(
    {
      _id: new ObjectId(req.user.userId),
    },
    {
      $set: {
        name,
        image,
        updatedAt: new Date(),
      },
    }
  );

  res.json({
    message: "Profile updated successfully",
  });
});


// Startup Ideas CRUD APIs
const startupIdeasCollection =
  db.collection("startup-ideas");

app.post("/ideas", verifyToken, async (req, res) => {
  const ideaData = {
    ...req.body,
    userId: new ObjectId(req.user.userId),
    createdAt: new Date(),
    updatedAt: new Date(),
    likes: 0,
    commentCount: 0,
  };

  const result =
    await startupIdeasCollection.insertOne(ideaData);

  res.status(201).json({
    message: "Idea created successfully",
    id: result.insertedId,
  });
});

app.get("/ideas", async (req, res) => {
  const result =
    await startupIdeasCollection.find().toArray();

  res.json(result);
});

app.get("/ideas/:id", async (req, res) => {
  const result =
    await startupIdeasCollection.findOne({
      _id: new ObjectId(req.params.id),
    });

  res.json(result);
});

app.patch("/ideas/:id", verifyToken, async (req, res) => {
  await startupIdeasCollection.updateOne(
    {
      _id: new ObjectId(req.params.id),
    },
    {
      $set: {
        ...req.body,
        updatedAt: new Date(),
      },
    }
  );

  res.json({
    message: "Idea updated successfully",
  });
});

app.delete("/ideas/:id", verifyToken, async (req, res) => {
  await startupIdeasCollection.deleteOne({
    _id: new ObjectId(req.params.id),
  });

  res.json({
    message: "Idea deleted successfully",
  });
});




