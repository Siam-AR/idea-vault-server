import express, { NextFunction, Request, Response } from "express";
import dotenv from "dotenv";
import cors from "cors";
import { MongoClient, ObjectId, ServerApiVersion } from "mongodb";
import jwt, { JwtPayload } from "jsonwebtoken";
import bcryptjs from "bcryptjs";

dotenv.config();

const uri = process.env.MONGODB_URI;
if (!uri) {
  throw new Error("MONGODB_URI is not defined");
}

const maskedUri = uri.replace(/\/\/([^:]+):([^@]+)@/, "//***:***@");
const JWT_SECRET = process.env.JWT_SECRET || "your-secret-key-change-in-production";
const DB_NAME = (process.env.MONGODB_DB_NAME || "community-spark").trim();
console.log(`MongoDB URI: ${maskedUri}`);
const CLIENT_URLS = (process.env.CLIENT_URL || process.env.CLIENT_URLS || "")
  .split(",")
  .map((url) => url.trim())
  .filter(Boolean);

const app = express();
const PORT = Number(process.env.PORT || 5000);

const corsOptions = CLIENT_URLS.length > 0 ? { origin: CLIENT_URLS, credentials: true } : { origin: true, credentials: true };

app.use(cors(corsOptions));
app.use(express.json());

const client = new MongoClient(uri, {
  serverApi: {
    version: ServerApiVersion.v1,
    strict: true,
    deprecationErrors: true,
  },
});

interface AuthUserPayload extends JwtPayload {
  userId?: string | ObjectId;
  email?: string;
  name?: string;
}

interface AuthRequest<Params = Record<string, any>, ResBody = any, ReqBody = any, Query = Record<string, any>>
  extends Request<Params, ResBody, ReqBody, Query> {
  user?: AuthUserPayload;
}

interface UserDocument {
  _id: ObjectId;
  name: string;
  email: string;
  password: string;
  image: string;
  googleId?: string;
  authMethod?: string;
  createdAt: Date;
  updatedAt: Date;
}

interface IdeaDocument {
  _id: ObjectId;
  title: string;
  shortDescription: string;
  detailedDescription: string;
  fullDescription?: string;
  category: string;
  tags: string[];
  imageURL: string;
  location?: string;
  supportNeeded?: string;
  priority?: string;
  estimatedBudget: string;
  targetAudience: string;
  problemStatement: string;
  proposedSolution: string;
  userId: ObjectId;
  userName: string;
  userEmail: string;
  createdAt: Date;
  updatedAt: Date;
  likes: number;
  commentCount: number;
}

interface CommentDocument {
  _id: ObjectId;
  ideaId: ObjectId;
  userId: ObjectId;
  text: string;
  userName?: string;
  userEmail?: string;
  userImage?: string;
  createdAt: Date;
  updatedAt: Date;
}

const verifyToken = async (req: AuthRequest, res: Response, next: NextFunction) => {
  const authHeader = req.headers.authorization;

  if (!authHeader) {
    return res.status(401).json({ message: "Unauthorized" });
  }

  const token = authHeader.split(" ")[1];
  if (!token) {
    return res.status(401).json({ message: "Unauthorized" });
  }

  try {
    const decoded = jwt.verify(token, JWT_SECRET) as AuthUserPayload;
    req.user = decoded;
    next();
  } catch (error) {
    return res.status(403).json({ message: "Forbidden" });
  }
};

async function run() {
  try {
    // await client.connect();

    const db = client.db(DB_NAME);
    const usersCollection = db.collection<UserDocument>("users");
    const communityIdeasCollection = db.collection<IdeaDocument>("community-ideas");
    const commentsCollection = db.collection<CommentDocument>("comments");
    console.log(`Using MongoDB database: ${DB_NAME}`);

    app.post("/auth/register", async (req: AuthRequest<{ name?: string; email?: string; password?: string; image?: string }>, res) => {
      try {
        const { name, email, password, image } = req.body;

        if (!email || !password || !name) {
          return res.status(400).json({ message: "Missing required fields" });
        }

        if (password.length < 6) {
          return res.status(400).json({ message: "Password must be at least 6 characters" });
        }

        if (!/[A-Z]/.test(password)) {
          return res.status(400).json({ message: "Password must contain at least one uppercase letter" });
        }

        if (!/[a-z]/.test(password)) {
          return res.status(400).json({ message: "Password must contain at least one lowercase letter" });
        }

        const existingUser = await usersCollection.findOne({ email });
        if (existingUser) {
          return res.status(409).json({ message: "User already exists" });
        }

        const hashedPassword = await bcryptjs.hash(password, 10);
        const newUser: Omit<UserDocument, "_id"> = {
          name,
          email,
          password: hashedPassword,
          image: image || "",
          createdAt: new Date(),
          updatedAt: new Date(),
        };

        const result = await usersCollection.insertOne(newUser as UserDocument);

        const token = jwt.sign({ userId: result.insertedId, email, name }, JWT_SECRET, { expiresIn: "7d" });

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
        res.status(500).json({ message: "Registration failed", error: (error as Error).message });
      }
    });

    app.post("/auth/login", async (req: AuthRequest<{ email?: string; password?: string }>, res) => {
      try {
        const { email, password } = req.body;

        if (!email || !password) {
          return res.status(400).json({ message: "Missing email or password" });
        }

        const user = await usersCollection.findOne({ email });
        if (!user) {
          return res.status(401).json({ message: "Invalid credentials" });
        }

        const isPasswordValid = await bcryptjs.compare(password, user.password);
        if (!isPasswordValid) {
          return res.status(401).json({ message: "Invalid credentials" });
        }

        const token = jwt.sign({ userId: user._id, email: user.email, name: user.name }, JWT_SECRET, { expiresIn: "7d" });

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
        res.status(500).json({ message: "Login failed", error: (error as Error).message });
      }
    });

    app.post("/auth/google", async (req: AuthRequest<{ name?: string; email?: string; image?: string; googleId?: string }>, res) => {
      try {
        const { name, email, image, googleId } = req.body;

        if (!email || !name) {
          return res.status(400).json({ message: "Missing required fields" });
        }

        let user = await usersCollection.findOne({ email });

        if (!user) {
          const newUser: Omit<UserDocument, "_id"> = {
            name,
            email,
            password: "",
            image: image || "",
            googleId: googleId || "",
            authMethod: "google",
            createdAt: new Date(),
            updatedAt: new Date(),
          };

          const result = await usersCollection.insertOne(newUser as UserDocument);
          user = { ...newUser, _id: result.insertedId };
        } else if (!user.googleId && !user.password) {
          await usersCollection.updateOne({ _id: user._id }, { $set: { googleId: googleId || "", authMethod: "google" } });
        }

        const token = jwt.sign({ userId: user._id, email: user.email, name: user.name }, JWT_SECRET, { expiresIn: "7d" });

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
        res.status(500).json({ message: "Google OAuth failed", error: (error as Error).message });
      }
    });

    app.get("/auth/user", verifyToken, async (req: AuthRequest, res) => {
      try {
        const userId = req.user?.userId;
        if (!userId) {
          return res.status(401).json({ message: "Unauthorized" });
        }

        const id = typeof userId === "string" ? userId : userId.toString();
        const user = await usersCollection.findOne({ _id: new ObjectId(id) });

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

    app.patch("/auth/user", verifyToken, async (req: AuthRequest<{ name?: string; image?: string }>, res) => {
      try {
        const { name, image } = req.body;
        const userId = req.user?.userId;

        if (!userId) {
          return res.status(401).json({ message: "Unauthorized" });
        }

        const id = typeof userId === "string" ? userId : userId.toString();
        const updateData: Partial<UserDocument> = {};

        if (name) updateData.name = name;
        if (image) updateData.image = image;
        updateData.updatedAt = new Date();

        const result = await usersCollection.updateOne({ _id: new ObjectId(id) }, { $set: updateData });

        if (result.matchedCount === 0) {
          return res.status(404).json({ message: "User not found" });
        }

        res.json({ message: "Profile updated successfully" });
      } catch (error) {
        console.error("Error updating profile:", error);
        res.status(500).json({ message: "Error updating profile" });
      }
    });

    app.get("/ideas/featured", async (req, res) => {
      try {
        const result = await communityIdeasCollection.find().limit(6).toArray();
        res.json(result);
      } catch (error) {
        console.error("Error fetching featured ideas:", error);
        res.status(500).json({ message: "Error fetching featured ideas" });
      }
    });

    app.get("/ideas", async (req, res) => {
      try {
        const category = typeof req.query.category === "string" ? req.query.category : undefined;
        const search = typeof req.query.search === "string" ? req.query.search : undefined;
        const dateFrom = typeof req.query.dateFrom === "string" ? req.query.dateFrom : undefined;
        const dateTo = typeof req.query.dateTo === "string" ? req.query.dateTo : undefined;

        const filter: Record<string, unknown> = {};

        if (category) {
          filter.category = category;
        }

        if (search) {
          filter.title = { $regex: search, $options: "i" };
        }

        if (dateFrom || dateTo) {
          const dateFilter: Record<string, unknown> = {};
          if (dateFrom) {
            dateFilter.$gte = new Date(dateFrom);
          }
          if (dateTo) {
            const endDate = new Date(dateTo);
            endDate.setHours(23, 59, 59, 999);
            dateFilter.$lte = endDate;
          }
          filter.createdAt = dateFilter;
        }

        const result = await communityIdeasCollection.find(filter).toArray();
        res.json(result);
      } catch (error) {
        console.error("Error fetching ideas:", error);
        res.status(500).json({ message: "Error fetching ideas" });
      }
    });

    app.get("/ideas/:id", async (req: Request<{ id: string }>, res) => {
      try {
        const { id } = req.params;
        if (!ObjectId.isValid(id)) {
          return res.status(404).json({ message: "Idea not found" });
        }

        const result = await communityIdeasCollection.findOne({ _id: new ObjectId(id) });
        if (!result) {
          return res.status(404).json({ message: "Idea not found" });
        }

        res.json(result);
      } catch (error) {
        console.error("Error fetching idea:", error);
        res.status(500).json({ message: "Error fetching idea" });
      }
    });

    app.post(
      "/ideas",
      verifyToken,
      async (
        req: AuthRequest<{ title?: string; shortDescription?: string; detailedDescription?: string; fullDescription?: string; category?: string; tags?: string[] | string; imageURL?: string; location?: string; supportNeeded?: string; priority?: string; estimatedBudget?: string | number; targetAudience?: string; problemStatement?: string; proposedSolution?: string; userName?: string; userEmail?: string }>,
        res,
      ) => {
        try {
          const {
            title,
            shortDescription,
            detailedDescription,
            fullDescription,
            category,
            tags,
            imageURL,
            location,
            supportNeeded,
            priority,
            estimatedBudget,
            targetAudience,
            problemStatement,
            proposedSolution,
            userName,
            userEmail,
          } = req.body;

          const normalizedFullDescription = String(fullDescription || detailedDescription || "").trim();
          const normalizedLocation = String(location || targetAudience || "").trim();
          const normalizedSupportNeeded = String(supportNeeded || problemStatement || "").trim();
          const normalizedPriority = String(priority || proposedSolution || "").trim();

          const requiredFields = [
            ["title", title],
            ["shortDescription", shortDescription],
            ["fullDescription", normalizedFullDescription],
            ["category", category],
            ["imageURL", imageURL],
            ["location", normalizedLocation],
            ["supportNeeded", normalizedSupportNeeded],
            ["priority", normalizedPriority],
          ] as const;

          const missingField = requiredFields.find(([, value]) => !String(value || "").trim());
          if (missingField) {
            return res.status(400).json({ message: `Missing required field: ${missingField[0]}` });
          }

          const rawUserId = req.user?.userId;
          const normalizedUserId = typeof rawUserId === "string" ? rawUserId : rawUserId?.toString?.();
          if (!normalizedUserId || !ObjectId.isValid(normalizedUserId)) {
            return res.status(401).json({ message: "Invalid user ID" });
          }

          const ideaData: Omit<IdeaDocument, "_id"> = {
            title: title!.trim(),
            shortDescription: shortDescription!.trim(),
            detailedDescription: normalizedFullDescription,
            fullDescription: normalizedFullDescription,
            category: category!.trim(),
            tags: Array.isArray(tags)
              ? tags.map((tag) => String(tag).trim()).filter(Boolean)
              : String(tags || "")
                  .split(",")
                  .map((tag) => tag.trim())
                  .filter(Boolean),
            imageURL: imageURL!.trim(),
            location: normalizedLocation,
            supportNeeded: normalizedSupportNeeded,
            priority: normalizedPriority,
            estimatedBudget: String(estimatedBudget || supportNeeded || "").trim(),
            targetAudience: normalizedLocation,
            problemStatement: normalizedSupportNeeded,
            proposedSolution: normalizedPriority,
            userId: new ObjectId(normalizedUserId),
            userName: String(userName || req.user?.name || "Anonymous").trim() || "Anonymous",
            userEmail: String(userEmail || req.user?.email || "").trim(),
            createdAt: new Date(),
            updatedAt: new Date(),
            likes: 0,
            commentCount: 0,
          };

          const result = await communityIdeasCollection.insertOne(ideaData as IdeaDocument);
          res.status(201).json({ message: "Idea created successfully", id: result.insertedId });
        } catch (error) {
          console.error("Error creating idea:", error);
          res.status(500).json({ message: "Error creating idea" });
        }
      },
    );

    app.patch("/ideas/:id", verifyToken, async (req: AuthRequest<{ id: string }, any, Partial<IdeaDocument>>, res) => {
      try {
        const { id } = req.params;
        const updatedData = { ...req.body, updatedAt: new Date() };

        const idea = await communityIdeasCollection.findOne({ _id: new ObjectId(id) });
        if (!idea) {
          return res.status(404).json({ message: "Idea not found" });
        }

        const userId = req.user?.userId;
        const normalizedUserId = typeof userId === "string" ? userId : userId?.toString?.();
        if (!normalizedUserId || idea.userId.toString() !== normalizedUserId) {
          return res.status(403).json({ message: "Forbidden" });
        }

        await communityIdeasCollection.updateOne({ _id: idea._id }, { $set: updatedData });
        res.json({ message: "Idea updated successfully" });
      } catch (error) {
        console.error("Error updating idea:", error);
        res.status(500).json({ message: "Error updating idea" });
      }
    });

    app.delete("/ideas/:id", verifyToken, async (req: AuthRequest<{ id: string }>, res) => {
      try {
        const { id } = req.params;
        const idea = await communityIdeasCollection.findOne({ _id: new ObjectId(id) });
        if (!idea) {
          return res.status(404).json({ message: "Idea not found" });
        }

        const userId = req.user?.userId;
        const normalizedUserId = typeof userId === "string" ? userId : userId?.toString?.();
        if (!normalizedUserId || idea.userId.toString() !== normalizedUserId) {
          return res.status(403).json({ message: "Forbidden" });
        }

        await communityIdeasCollection.deleteOne({ _id: idea._id });
        res.json({ message: "Idea deleted successfully" });
      } catch (error) {
        console.error("Error deleting idea:", error);
        res.status(500).json({ message: "Error deleting idea" });
      }
    });

    app.get("/user/ideas", verifyToken, async (req: AuthRequest, res) => {
      try {
        const userId = req.user?.userId;
        if (!userId) {
          return res.status(401).json({ message: "Unauthorized" });
        }

        const normalizedUserId = typeof userId === "string" ? userId : userId.toString();
        const result = await communityIdeasCollection.find({ userId: new ObjectId(normalizedUserId) }).toArray();
        res.json(result);
      } catch (error) {
        console.error("Error fetching user ideas:", error);
        res.status(500).json({ message: "Error fetching user ideas" });
      }
    });

    const normalizeObjectId = (value?: ObjectId | string | null): ObjectId | null => {
      if (!value) return null;
      if (typeof value === "string") {
        return ObjectId.isValid(value) ? new ObjectId(value) : null;
      }
      return value;
    };

    const normalizeIdString = (value?: ObjectId | string | null): string | undefined => {
      if (!value) return undefined;
      return typeof value === "string" ? value : value.toString();
    };

    const buildCommentResponse = async (comment: CommentDocument) => {
      const user = await usersCollection.findOne(
        { _id: comment.userId },
        { projection: { name: 1, image: 1, email: 1 } },
      );

      const ideaQueryId = normalizeObjectId(comment.ideaId);
      const idea = ideaQueryId
        ? await communityIdeasCollection.findOne(
            { _id: ideaQueryId },
            { projection: { title: 1, category: 1, userName: 1, userEmail: 1 } },
          )
        : null;

      const ideaAuthorName = idea?.userName || idea?.userEmail || "Anonymous builder";

      return {
        _id: normalizeIdString(comment._id) || "",
        ideaId: normalizeIdString(comment.ideaId),
        userId: normalizeIdString(comment.userId),
        text: comment.text,
        createdAt: comment.createdAt?.toISOString(),
        updatedAt: comment.updatedAt?.toISOString(),
        userName: user?.name || "Anonymous",
        userEmail: user?.email || "",
        userImage: user?.image || "",
        ideaTitle: idea?.title,
        ideaCategory: idea?.category,
        ideaAuthorName,
        idea: idea
          ? {
              _id: normalizeIdString(idea._id) || "",
              title: idea.title,
              category: idea.category,
              authorName: ideaAuthorName,
            }
          : undefined,
      };
    };

    app.post("/comments", verifyToken, async (req: AuthRequest<{ ideaId?: string; text?: string }>, res) => {
      try {
        const { ideaId, text } = req.body;
        if (!ideaId || !text || !String(text).trim()) {
          return res.status(400).json({ message: "Missing required fields" });
        }

        const userId = req.user?.userId;
        if (!userId) {
          return res.status(401).json({ message: "Unauthorized" });
        }

        const normalizedUserId = typeof userId === "string" ? userId : userId.toString();
        const commentData: Omit<CommentDocument, "_id"> = {
          ideaId: new ObjectId(ideaId),
          userId: new ObjectId(normalizedUserId),
          text: String(text).trim(),
          createdAt: new Date(),
          updatedAt: new Date(),
        };

        const result = await commentsCollection.insertOne(commentData as CommentDocument);
        await communityIdeasCollection.updateOne({ _id: new ObjectId(ideaId) }, { $inc: { commentCount: 1 } });

        const comment = await commentsCollection.findOne({ _id: result.insertedId });
        if (!comment) {
          return res.status(500).json({ message: "Comment creation failed" });
        }

        res.status(201).json(await buildCommentResponse(comment));
      } catch (error) {
        console.error("Error creating comment:", error);
        res.status(500).json({ message: "Error creating comment" });
      }
    });

    app.get("/comments/me", verifyToken, async (req: AuthRequest, res) => {
      try {
        const userId = req.user?.userId;
        if (!userId) {
          return res.status(401).json({ message: "Unauthorized" });
        }

        const normalizedUserId = typeof userId === "string" ? userId : userId.toString();
        const comments = await commentsCollection.find({ userId: new ObjectId(normalizedUserId) }).toArray();
        const response = await Promise.all(comments.map(buildCommentResponse));
        res.json(response);
      } catch (error) {
        console.error("Error fetching user comments:", error);
        res.status(500).json({ message: "Error fetching user comments" });
      }
    });

    app.get("/comments/:ideaId", async (req: Request<{ ideaId: string }>, res) => {
      try {
        const { ideaId } = req.params;
        const comments = await commentsCollection.find({ ideaId: new ObjectId(ideaId) }).toArray();
        const response = await Promise.all(comments.map(buildCommentResponse));
        res.json(response);
      } catch (error) {
        console.error("Error fetching idea comments:", error);
        res.status(500).json({ message: "Error fetching idea comments" });
      }
    });

    app.delete("/comments/:commentId", verifyToken, async (req: AuthRequest<{ commentId: string }>, res) => {
      try {
        const { commentId } = req.params;
        const comment = await commentsCollection.findOne({ _id: new ObjectId(commentId) });
        if (!comment) {
          return res.status(404).json({ message: "Comment not found" });
        }

        const userId = req.user?.userId;
        const normalizedUserId = typeof userId === "string" ? userId : userId?.toString?.();
        if (!normalizedUserId || comment.userId.toString() !== normalizedUserId) {
          return res.status(403).json({ message: "Forbidden" });
        }

        await commentsCollection.deleteOne({ _id: comment._id });
        res.json({ message: "Comment deleted successfully" });
      } catch (error) {
        console.error("Error deleting comment:", error);
        res.status(500).json({ message: "Error deleting comment" });
      }
    });

    app.patch("/comments/:commentId", verifyToken, async (req: AuthRequest<{ commentId: string }, any, { text?: string }>, res) => {
      try {
        const { commentId } = req.params;
        const { text } = req.body;

        if (!text || !String(text).trim()) {
          return res.status(400).json({ message: "Missing or invalid text" });
        }

        const comment = await commentsCollection.findOne({ _id: new ObjectId(commentId) });
        if (!comment) {
          return res.status(404).json({ message: "Comment not found" });
        }

        const userId = req.user?.userId;
        const normalizedUserId = typeof userId === "string" ? userId : userId?.toString?.();
        if (!normalizedUserId || comment.userId.toString() !== normalizedUserId) {
          return res.status(403).json({ message: "Forbidden" });
        }

        await commentsCollection.updateOne({ _id: comment._id }, { $set: { text: String(text).trim(), updatedAt: new Date() } });
        res.json({ message: "Comment updated successfully" });
      } catch (error) {
        console.error("Error updating comment:", error);
        res.status(500).json({ message: "Error updating comment" });
      }
    });

    console.log("Pinged your deployment. You successfully connected to MongoDB!");
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

export default app;
