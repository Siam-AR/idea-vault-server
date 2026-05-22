const express = require("express");
const dotenv = require("dotenv");
const cors = require("cors");
const { MongoClient, ServerApiVersion, ObjectId } = require("mongodb");
const jwt = require("jsonwebtoken");
const bcryptjs = require("bcryptjs");

dotenv.config();

const uri = process.env.MONGODB_URI;
const JWT_SECRET = process.env.JWT_SECRET || "your-secret-key-change-in-production";
const CLIENT_URL = process.env.CLIENT_URL || "http://localhost:3000";

const app = express();
const PORT = process.env.PORT;

app.use(cors({ origin: CLIENT_URL }));
app.use(express.json());

const client = new MongoClient(uri, {
  serverApi: {
    version: ServerApiVersion.v1,
    strict: true,
    deprecationErrors: true,
  },
});

// Middleware to verify JWT token
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

async function run() {
  try {
    // await client.connect();

    const db = client.db("idea-vault");
    const usersCollection = db.collection("users");
    const startupIdeasCollection = db.collection("startup-ideas");
    const commentsCollection = db.collection("comments");

    // ==================== AUTHENTICATION ROUTES ====================

    // Register Route
    app.post("/auth/register", async (req, res) => {
      try {
        const { name, email, password, image } = req.body;

        // Validation
        if (!email || !password || !name) {
          return res.status(400).json({ message: "Missing required fields" });
        }

        // Validate password
        if (password.length < 6) {
          return res
            .status(400)
            .json({ message: "Password must be at least 6 characters" });
        }

        if (!/[A-Z]/.test(password)) {
          return res.status(400).json({
            message: "Password must contain at least one uppercase letter",
          });
        }

        if (!/[a-z]/.test(password)) {
          return res.status(400).json({
            message: "Password must contain at least one lowercase letter",
          });
        }

        // Check if user already exists
        const existingUser = await usersCollection.findOne({ email });
        if (existingUser) {
          return res.status(409).json({ message: "User already exists" });
        }

        // Hash password
        const hashedPassword = await bcryptjs.hash(password, 10);

        // Create new user
        const newUser = {
          name,
          email,
          password: hashedPassword,
          image: image || "",
          createdAt: new Date(),
          updatedAt: new Date(),
        };

        const result = await usersCollection.insertOne(newUser);

        // Generate JWT token
        const token = jwt.sign(
          { userId: result.insertedId, email, name },
          JWT_SECRET,
          { expiresIn: "7d" }
        );

        res.status(201).json({
          message: "User registered successfully",
          token,
          user: {
            id: result.insertedId,
            name,
            email,
            image: image || "",
          },
        });
      } catch (error) {
        console.error("Registration error:", error);
        res.status(500).json({ message: "Registration failed", error: error.message });
      }
    });

    // Login Route
    app.post("/auth/login", async (req, res) => {
      try {
        const { email, password } = req.body;

        // Validation
        if (!email || !password) {
          return res.status(400).json({ message: "Missing email or password" });
        }

        // Find user
        const user = await usersCollection.findOne({ email });
        if (!user) {
          return res.status(401).json({ message: "Invalid credentials" });
        }

        // Verify password
        const isPasswordValid = await bcryptjs.compare(password, user.password);
        if (!isPasswordValid) {
          return res.status(401).json({ message: "Invalid credentials" });
        }

        // Generate JWT token
        const token = jwt.sign(
          { userId: user._id, email: user.email, name: user.name },
          JWT_SECRET,
          { expiresIn: "7d" }
        );

        res.json({
          message: "Login successful",
          token,
          user: {
            id: user._id,
            name: user.name,
            email: user.email,
            image: user.image || "",
          },
        });
      } catch (error) {
        console.error("Login error:", error);
        res.status(500).json({ message: "Login failed", error: error.message });
      }
    });

    // Google OAuth Route
    app.post("/auth/google", async (req, res) => {
      try {
        const { name, email, image, googleId } = req.body;

        // Validation
        if (!email || !name) {
          return res.status(400).json({ message: "Missing required fields" });
        }

        // Check if user exists
        let user = await usersCollection.findOne({ email });

        if (!user) {
          // Create new user if doesn't exist
          const newUser = {
            name,
            email,
            password: "", // Google users don't have password
            image: image || "",
            googleId: googleId || "",
            authMethod: "google",
            createdAt: new Date(),
            updatedAt: new Date(),
          };

          const result = await usersCollection.insertOne(newUser);
          user = { ...newUser, _id: result.insertedId };
        } else if (!user.googleId && !user.password) {
          // Update existing user with google ID if they don't have password
          await usersCollection.updateOne(
            { _id: user._id },
            { $set: { googleId: googleId || "", authMethod: "google" } }
          );
        }

        // Generate JWT token
        const token = jwt.sign(
          { userId: user._id, email: user.email, name: user.name },
          JWT_SECRET,
          { expiresIn: "7d" }
        );

        res.json({
          message: "Google login successful",
          token,
          user: {
            id: user._id,
            name: user.name,
            email: user.email,
            image: user.image || "",
          },
        });
      } catch (error) {
        console.error("Google OAuth error:", error);
        res.status(500).json({ message: "Google OAuth failed", error: error.message });
      }
    });

    // Get User Profile
    app.get("/auth/user", verifyToken, async (req, res) => {
      try {
        const user = await usersCollection.findOne({
          _id: new ObjectId(req.user.userId),
        });

        if (!user) {
          return res.status(404).json({ message: "User not found" });
        }

        res.json({
          user: {
            id: user._id,
            name: user.name,
            email: user.email,
            image: user.image || "",
          },
        });
      } catch (error) {
        console.error("Error fetching user:", error);
        res.status(500).json({ message: "Error fetching user" });
      }
    });

    // Update User Profile
    app.patch("/auth/user", verifyToken, async (req, res) => {
      try {
        const { name, image } = req.body;
        const userId = req.user.userId;

        const updateData = {};
        if (name) updateData.name = name;
        if (image) updateData.image = image;
        updateData.updatedAt = new Date();

        const result = await usersCollection.updateOne(
          { _id: new ObjectId(userId) },
          { $set: updateData }
        );

        if (result.matchedCount === 0) {
          return res.status(404).json({ message: "User not found" });
        }

        res.json({ message: "Profile updated successfully" });
      } catch (error) {
        console.error("Error updating profile:", error);
        res.status(500).json({ message: "Error updating profile" });
      }
    });

    // ==================== IDEAS ROUTES ====================

    // Featured Ideas
    app.get("/ideas/featured", async (req, res) => {
      try {
        const result = await startupIdeasCollection
          .find()
          .limit(6)
          .toArray();
        res.json(result);
      } catch (error) {
        console.error("Error fetching featured ideas:", error);
        res.status(500).json({ message: "Error fetching featured ideas" });
      }
    });

    // Get All Ideas
    app.get("/ideas", async (req, res) => {
      try {
        const { category, search, dateFrom, dateTo } = req.query;
        let filter = {};

        if (category) {
          filter.category = category;
        }

        if (search) {
          filter.title = { $regex: search, $options: "i" };
        }

        if (dateFrom || dateTo) {
          filter.createdAt = {};

          if (dateFrom) {
            filter.createdAt.$gte = new Date(dateFrom);
          }

          if (dateTo) {
            const endDate = new Date(dateTo);
            endDate.setHours(23, 59, 59, 999);
            filter.createdAt.$lte = endDate;
          }
        }

        const result = await startupIdeasCollection.find(filter).toArray();
        res.json(result);
      } catch (error) {
        console.error("Error fetching ideas:", error);
        res.status(500).json({ message: "Error fetching ideas" });
      }
    });

    // Get Single Idea
    app.get("/ideas/:id", async (req, res) => {
      try {
        const { id } = req.params;

        if (!ObjectId.isValid(id)) {
          return res.status(404).json({ message: "Idea not found" });
        }

        const result = await startupIdeasCollection.findOne({
          _id: new ObjectId(id),
        });

        if (!result) {
          return res.status(404).json({ message: "Idea not found" });
        }

        res.json(result);
      } catch (error) {
        console.error("Error fetching idea:", error);
        res.status(500).json({ message: "Error fetching idea" });
      }
    });

    // Add New Idea
    app.post("/ideas", verifyToken, async (req, res) => {
      try {
        const {
          title,
          shortDescription,
          detailedDescription,
          category,
          tags,
          imageURL,
          estimatedBudget,
          targetAudience,
          problemStatement,
          proposedSolution,
        } = req.body;

        const requiredFields = [
          ["title", title],
          ["shortDescription", shortDescription],
          ["detailedDescription", detailedDescription],
          ["category", category],
          ["imageURL", imageURL],
          ["targetAudience", targetAudience],
          ["problemStatement", problemStatement],
          ["proposedSolution", proposedSolution],
        ];

        const missingField = requiredFields.find(([, value]) =>
          !String(value || "").trim()
        );

        if (missingField) {
          return res
            .status(400)
            .json({ message: `Missing required field: ${missingField[0]}` });
        }

        const rawUserId = req.user?.userId;
        const normalizedUserId =
          typeof rawUserId === "string"
            ? rawUserId
            : rawUserId?.$oid || rawUserId?.id || rawUserId?.toString?.();

        if (!normalizedUserId || !ObjectId.isValid(normalizedUserId)) {
          return res.status(401).json({ message: "Invalid or expired session. Please log in again." });
        }

        const ideaData = {
          title: title.trim(),
          shortDescription: shortDescription.trim(),
          detailedDescription: detailedDescription.trim(),
          category: category.trim(),
          tags: Array.isArray(tags)
            ? tags.map((tag) => String(tag).trim()).filter(Boolean)
            : String(tags || "")
                .split(",")
                .map((tag) => tag.trim())
                .filter(Boolean),
          imageURL: imageURL.trim(),
          estimatedBudget: String(estimatedBudget || "").trim(),
          targetAudience: targetAudience.trim(),
          problemStatement: problemStatement.trim(),
          proposedSolution: proposedSolution.trim(),
          userId: new ObjectId(normalizedUserId),
          userName: String(req.body.userName || req.user.name || "Anonymous").trim() || "Anonymous",
          userEmail: String(req.body.userEmail || req.user.email || "").trim(),
          createdAt: new Date(),
          updatedAt: new Date(),
          likes: 0,
          commentCount: 0,
        };

        const result = await startupIdeasCollection.insertOne(ideaData);
        res.status(201).json({
          message: "Idea created successfully",
          id: result.insertedId,
        });
      } catch (error) {
        console.error("Error creating idea:", error);
        res.status(500).json({ message: "Error creating idea" });
      }
    });

    // Update Idea
    app.patch("/ideas/:id", verifyToken, async (req, res) => {
      try {
        const { id } = req.params;
        const updatedData = {
          ...req.body,
          updatedAt: new Date(),
        };

        const idea = await startupIdeasCollection.findOne({
          _id: new ObjectId(id),
        });

        if (!idea) {
          return res.status(404).json({ message: "Idea not found" });
        }

        if (idea.userId.toString() !== req.user.userId.toString()) {
          return res
            .status(403)
            .json({ message: "You can only update your own ideas" });
        }

        const result = await startupIdeasCollection.updateOne(
          { _id: new ObjectId(id) },
          { $set: updatedData }
        );

        res.json({ message: "Idea updated successfully" });
      } catch (error) {
        console.error("Error updating idea:", error);
        res.status(500).json({ message: "Error updating idea" });
      }
    });

    // Delete Idea
    app.delete("/ideas/:id", verifyToken, async (req, res) => {
      try {
        const { id } = req.params;

        const idea = await startupIdeasCollection.findOne({
          _id: new ObjectId(id),
        });

        if (!idea) {
          return res.status(404).json({ message: "Idea not found" });
        }

        if (idea.userId.toString() !== req.user.userId.toString()) {
          return res
            .status(403)
            .json({ message: "You can only delete your own ideas" });
        }

        const result = await startupIdeasCollection.deleteOne({
          _id: new ObjectId(id),
        });

        // Also delete associated comments
        await commentsCollection.deleteMany({ ideaId: new ObjectId(id) });

        res.json({ message: "Idea deleted successfully" });
      } catch (error) {
        console.error("Error deleting idea:", error);
        res.status(500).json({ message: "Error deleting idea" });
      }
    });

    // Get User's Ideas
    app.get("/user/ideas", verifyToken, async (req, res) => {
      try {
        const userId = new ObjectId(req.user.userId);
        const result = await startupIdeasCollection
          .find({ userId })
          .toArray();
        res.json(result);
      } catch (error) {
        console.error("Error fetching user ideas:", error);
        res.status(500).json({ message: "Error fetching user ideas" });
      }
    });

    // ==================== COMMENTS ROUTES ====================

    const buildCommentResponse = async (comment) => {
      const user = await usersCollection.findOne(
        { _id: comment.userId },
        { projection: { name: 1, image: 1, email: 1 } }
      );

      return {
        _id: comment._id,
        ideaId: comment.ideaId,
        userId: comment.userId,
        text: comment.text,
        createdAt: comment.createdAt,
        updatedAt: comment.updatedAt,
        userName: user?.name || "Anonymous",
        userEmail: user?.email || "",
        userImage: user?.image || "",
      };
    };

    // Add Comment
    app.post("/comments", verifyToken, async (req, res) => {
      try {
        const { ideaId, text } = req.body;

        if (!ideaId || !text) {
          return res.status(400).json({ message: "Missing required fields" });
        }

        const commentData = {
          ideaId: new ObjectId(ideaId),
          userId: new ObjectId(req.user.userId),
          text,
          createdAt: new Date(),
          updatedAt: new Date(),
        };

        const result = await commentsCollection.insertOne(commentData);

        // Increment comment count on idea
        await startupIdeasCollection.updateOne(
          { _id: new ObjectId(ideaId) },
          { $inc: { commentCount: 1 } }
        );

        const savedComment = await commentsCollection.findOne({ _id: result.insertedId });
        res.status(201).json(await buildCommentResponse(savedComment));
      } catch (error) {
        console.error("Error adding comment:", error);
        res.status(500).json({ message: "Error adding comment" });
      }
    });

    // Get authenticated user's comments
    app.get("/comments/me", verifyToken, async (req, res) => {
      try {
        const rawUserId = req.user?.userId;
        const normalizedUserId =
          typeof rawUserId === "string"
            ? rawUserId
            : rawUserId?.$oid || rawUserId?.id || rawUserId?.toString?.();

        if (!normalizedUserId || !ObjectId.isValid(normalizedUserId)) {
          return res.status(401).json({ message: "Invalid or expired session. Please log in again." });
        }

        const userId = new ObjectId(normalizedUserId);
        const comments = await commentsCollection
          .find({ userId })
          .sort({ updatedAt: -1, createdAt: -1 })
          .toArray();

        const commentsWithContext = await Promise.all(
          comments.map(async (comment) => {
            const [commentResponse, idea] = await Promise.all([
              buildCommentResponse(comment),
              startupIdeasCollection.findOne(
                { _id: comment.ideaId },
                { projection: { title: 1, category: 1, imageURL: 1, userName: 1, userEmail: 1 } }
              ),
            ]);

            return {
              ...commentResponse,
              idea: idea
                ? {
                    _id: idea._id,
                    title: idea.title,
                    category: idea.category,
                    imageURL: idea.imageURL,
                    authorName: idea.userName || idea.userEmail || "Anonymous",
                  }
                : null,
            };
          })
        );

        res.json(commentsWithContext);
      } catch (error) {
        console.error("Error fetching user comments:", error);
        res.status(500).json({ message: "Error fetching user comments" });
      }
    });

    // Get Comments for an Idea
    app.get("/comments/:ideaId", async (req, res) => {
      try {
        const { ideaId } = req.params;
        const comments = await commentsCollection
          .find({ ideaId: new ObjectId(ideaId) })
          .sort({ createdAt: 1 })
          .toArray();

        const commentsWithUsers = await Promise.all(
          comments.map((comment) => buildCommentResponse(comment))
        );

        res.json(commentsWithUsers);
      } catch (error) {
        console.error("Error fetching comments:", error);
        res.status(500).json({ message: "Error fetching comments" });
      }
    });

    // Delete Comment
    app.delete("/comments/:commentId", verifyToken, async (req, res) => {
      try {
        const { commentId } = req.params;

        const comment = await commentsCollection.findOne({
          _id: new ObjectId(commentId),
        });

        if (!comment) {
          return res.status(404).json({ message: "Comment not found" });
        }

        if (comment.userId.toString() !== req.user.userId.toString()) {
          return res
            .status(403)
            .json({ message: "You can only delete your own comments" });
        }

        await commentsCollection.deleteOne({
          _id: new ObjectId(commentId),
        });

        // Decrement comment count on idea
        await startupIdeasCollection.updateOne(
          { _id: comment.ideaId },
          { $inc: { commentCount: -1 } }
        );

        res.json({ message: "Comment deleted successfully" });
      } catch (error) {
        console.error("Error deleting comment:", error);
        res.status(500).json({ message: "Error deleting comment" });
      }
    });

    // Update Comment
    app.patch("/comments/:commentId", verifyToken, async (req, res) => {
      try {
        const { commentId } = req.params;
        const { text } = req.body;

        const comment = await commentsCollection.findOne({
          _id: new ObjectId(commentId),
        });

        if (!comment) {
          return res.status(404).json({ message: "Comment not found" });
        }

        if (comment.userId.toString() !== req.user.userId.toString()) {
          return res
            .status(403)
            .json({ message: "You can only edit your own comments" });
        }

        await commentsCollection.updateOne(
          { _id: new ObjectId(commentId) },
          { $set: { text, updatedAt: new Date() } }
        );

        const updatedComment = await commentsCollection.findOne({ _id: new ObjectId(commentId) });
        res.json(await buildCommentResponse(updatedComment));
      } catch (error) {
        console.error("Error updating comment:", error);
        res.status(500).json({ message: "Error updating comment" });
      }
    });

    console.log(
      "Pinged your deployment. You successfully connected to MongoDB!"
    );
  } finally {
    // await client.close();
  }
}

run().catch(console.dir);

app.get("/", (req, res) => {
  res.send("Server is running fine!");
});

if (process.env.VERCEL !== "1") {
  app.listen(PORT, () => {
    console.log(`Server running on port ${PORT}`);
  });
}

module.exports = app;