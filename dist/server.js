"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
const express_1 = __importDefault(require("express"));
const dotenv_1 = __importDefault(require("dotenv"));
const cors_1 = __importDefault(require("cors"));
const mongodb_1 = require("mongodb");
const jsonwebtoken_1 = __importDefault(require("jsonwebtoken"));
const bcryptjs_1 = __importDefault(require("bcryptjs"));
dotenv_1.default.config();
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
const app = (0, express_1.default)();
const PORT = Number(process.env.PORT || 5000);
const corsOptions = CLIENT_URLS.length > 0 ? { origin: CLIENT_URLS, credentials: true } : { origin: true, credentials: true };
app.use((0, cors_1.default)(corsOptions));
app.use(express_1.default.json());
const client = new mongodb_1.MongoClient(uri, {
    serverApi: {
        version: mongodb_1.ServerApiVersion.v1,
        strict: true,
        deprecationErrors: true,
    },
});
const verifyToken = async (req, res, next) => {
    const authHeader = req.headers.authorization;
    if (!authHeader) {
        return res.status(401).json({ message: "Unauthorized" });
    }
    const token = authHeader.split(" ")[1];
    if (!token) {
        return res.status(401).json({ message: "Unauthorized" });
    }
    try {
        const decoded = jsonwebtoken_1.default.verify(token, JWT_SECRET);
        req.user = decoded;
        next();
    }
    catch (error) {
        return res.status(403).json({ message: "Forbidden" });
    }
};
async function run() {
    try {
        // await client.connect();
        const db = client.db(DB_NAME);
        const usersCollection = db.collection("users");
        const communityIdeasCollection = db.collection("community-ideas");
        const commentsCollection = db.collection("comments");
        console.log(`Using MongoDB database: ${DB_NAME}`);
        app.post("/auth/register", async (req, res) => {
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
                const hashedPassword = await bcryptjs_1.default.hash(password, 10);
                const newUser = {
                    name,
                    email,
                    password: hashedPassword,
                    image: image || "",
                    createdAt: new Date(),
                    updatedAt: new Date(),
                };
                const result = await usersCollection.insertOne(newUser);
                const token = jsonwebtoken_1.default.sign({ userId: result.insertedId, email, name }, JWT_SECRET, { expiresIn: "7d" });
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
            }
            catch (error) {
                console.error("Registration error:", error);
                res.status(500).json({ message: "Registration failed", error: error.message });
            }
        });
        app.post("/auth/login", async (req, res) => {
            try {
                const { email, password } = req.body;
                if (!email || !password) {
                    return res.status(400).json({ message: "Missing email or password" });
                }
                const user = await usersCollection.findOne({ email });
                if (!user) {
                    return res.status(401).json({ message: "Invalid credentials" });
                }
                const isPasswordValid = await bcryptjs_1.default.compare(password, user.password);
                if (!isPasswordValid) {
                    return res.status(401).json({ message: "Invalid credentials" });
                }
                const token = jsonwebtoken_1.default.sign({ userId: user._id, email: user.email, name: user.name }, JWT_SECRET, { expiresIn: "7d" });
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
            }
            catch (error) {
                console.error("Login error:", error);
                res.status(500).json({ message: "Login failed", error: error.message });
            }
        });
        app.post("/auth/google", async (req, res) => {
            try {
                const { name, email, image, googleId } = req.body;
                if (!email || !name) {
                    return res.status(400).json({ message: "Missing required fields" });
                }
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
                    user = { ...newUser, _id: result.insertedId };
                }
                else if (!user.googleId && !user.password) {
                    await usersCollection.updateOne({ _id: user._id }, { $set: { googleId: googleId || "", authMethod: "google" } });
                }
                const token = jsonwebtoken_1.default.sign({ userId: user._id, email: user.email, name: user.name }, JWT_SECRET, { expiresIn: "7d" });
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
            }
            catch (error) {
                console.error("Google OAuth error:", error);
                res.status(500).json({ message: "Google OAuth failed", error: error.message });
            }
        });
        app.get("/auth/user", verifyToken, async (req, res) => {
            try {
                const userId = req.user?.userId;
                if (!userId) {
                    return res.status(401).json({ message: "Unauthorized" });
                }
                const id = typeof userId === "string" ? userId : userId.toString();
                const user = await usersCollection.findOne({ _id: new mongodb_1.ObjectId(id) });
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
            }
            catch (error) {
                console.error("Error fetching user:", error);
                res.status(500).json({ message: "Error fetching user" });
            }
        });
        app.patch("/auth/user", verifyToken, async (req, res) => {
            try {
                const { name, image } = req.body;
                const userId = req.user?.userId;
                if (!userId) {
                    return res.status(401).json({ message: "Unauthorized" });
                }
                const id = typeof userId === "string" ? userId : userId.toString();
                const updateData = {};
                if (name)
                    updateData.name = name;
                if (image)
                    updateData.image = image;
                updateData.updatedAt = new Date();
                const result = await usersCollection.updateOne({ _id: new mongodb_1.ObjectId(id) }, { $set: updateData });
                if (result.matchedCount === 0) {
                    return res.status(404).json({ message: "User not found" });
                }
                res.json({ message: "Profile updated successfully" });
            }
            catch (error) {
                console.error("Error updating profile:", error);
                res.status(500).json({ message: "Error updating profile" });
            }
        });
        app.get("/ideas/featured", async (req, res) => {
            try {
                const result = await communityIdeasCollection.find().limit(6).toArray();
                res.json(result);
            }
            catch (error) {
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
                const filter = {};
                if (category) {
                    filter.category = category;
                }
                if (search) {
                    filter.title = { $regex: search, $options: "i" };
                }
                if (dateFrom || dateTo) {
                    const dateFilter = {};
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
            }
            catch (error) {
                console.error("Error fetching ideas:", error);
                res.status(500).json({ message: "Error fetching ideas" });
            }
        });
        app.get("/ideas/:id", async (req, res) => {
            try {
                const { id } = req.params;
                if (!mongodb_1.ObjectId.isValid(id)) {
                    return res.status(404).json({ message: "Idea not found" });
                }
                const result = await communityIdeasCollection.findOne({ _id: new mongodb_1.ObjectId(id) });
                if (!result) {
                    return res.status(404).json({ message: "Idea not found" });
                }
                res.json(result);
            }
            catch (error) {
                console.error("Error fetching idea:", error);
                res.status(500).json({ message: "Error fetching idea" });
            }
        });
        app.post("/ideas", verifyToken, async (req, res) => {
            try {
                const { title, shortDescription, detailedDescription, category, tags, imageURL, estimatedBudget, targetAudience, problemStatement, proposedSolution, userName, userEmail, } = req.body;
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
                const missingField = requiredFields.find(([, value]) => !String(value || "").trim());
                if (missingField) {
                    return res.status(400).json({ message: `Missing required field: ${missingField[0]}` });
                }
                const rawUserId = req.user?.userId;
                const normalizedUserId = typeof rawUserId === "string" ? rawUserId : rawUserId?.toString?.();
                if (!normalizedUserId || !mongodb_1.ObjectId.isValid(normalizedUserId)) {
                    return res.status(401).json({ message: "Invalid user ID" });
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
                    userId: new mongodb_1.ObjectId(normalizedUserId),
                    userName: String(userName || req.user?.name || "Anonymous").trim() || "Anonymous",
                    userEmail: String(userEmail || req.user?.email || "").trim(),
                    createdAt: new Date(),
                    updatedAt: new Date(),
                    likes: 0,
                    commentCount: 0,
                };
                const result = await communityIdeasCollection.insertOne(ideaData);
                res.status(201).json({ message: "Idea created successfully", id: result.insertedId });
            }
            catch (error) {
                console.error("Error creating idea:", error);
                res.status(500).json({ message: "Error creating idea" });
            }
        });
        app.patch("/ideas/:id", verifyToken, async (req, res) => {
            try {
                const { id } = req.params;
                const updatedData = { ...req.body, updatedAt: new Date() };
                const idea = await communityIdeasCollection.findOne({ _id: new mongodb_1.ObjectId(id) });
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
            }
            catch (error) {
                console.error("Error updating idea:", error);
                res.status(500).json({ message: "Error updating idea" });
            }
        });
        app.delete("/ideas/:id", verifyToken, async (req, res) => {
            try {
                const { id } = req.params;
                const idea = await communityIdeasCollection.findOne({ _id: new mongodb_1.ObjectId(id) });
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
            }
            catch (error) {
                console.error("Error deleting idea:", error);
                res.status(500).json({ message: "Error deleting idea" });
            }
        });
        app.get("/user/ideas", verifyToken, async (req, res) => {
            try {
                const userId = req.user?.userId;
                if (!userId) {
                    return res.status(401).json({ message: "Unauthorized" });
                }
                const normalizedUserId = typeof userId === "string" ? userId : userId.toString();
                const result = await communityIdeasCollection.find({ userId: new mongodb_1.ObjectId(normalizedUserId) }).toArray();
                res.json(result);
            }
            catch (error) {
                console.error("Error fetching user ideas:", error);
                res.status(500).json({ message: "Error fetching user ideas" });
            }
        });
        const normalizeObjectId = (value) => {
            if (!value)
                return null;
            if (typeof value === "string") {
                return mongodb_1.ObjectId.isValid(value) ? new mongodb_1.ObjectId(value) : null;
            }
            return value;
        };
        const normalizeIdString = (value) => {
            if (!value)
                return undefined;
            return typeof value === "string" ? value : value.toString();
        };
        const buildCommentResponse = async (comment) => {
            const user = await usersCollection.findOne({ _id: comment.userId }, { projection: { name: 1, image: 1, email: 1 } });
            const ideaQueryId = normalizeObjectId(comment.ideaId);
            const idea = ideaQueryId
                ? await communityIdeasCollection.findOne({ _id: ideaQueryId }, { projection: { title: 1, category: 1, userName: 1, userEmail: 1 } })
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
        app.post("/comments", verifyToken, async (req, res) => {
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
                const commentData = {
                    ideaId: new mongodb_1.ObjectId(ideaId),
                    userId: new mongodb_1.ObjectId(normalizedUserId),
                    text: String(text).trim(),
                    createdAt: new Date(),
                    updatedAt: new Date(),
                };
                const result = await commentsCollection.insertOne(commentData);
                await communityIdeasCollection.updateOne({ _id: new mongodb_1.ObjectId(ideaId) }, { $inc: { commentCount: 1 } });
                const comment = await commentsCollection.findOne({ _id: result.insertedId });
                if (!comment) {
                    return res.status(500).json({ message: "Comment creation failed" });
                }
                res.status(201).json(await buildCommentResponse(comment));
            }
            catch (error) {
                console.error("Error creating comment:", error);
                res.status(500).json({ message: "Error creating comment" });
            }
        });
        app.get("/comments/me", verifyToken, async (req, res) => {
            try {
                const userId = req.user?.userId;
                if (!userId) {
                    return res.status(401).json({ message: "Unauthorized" });
                }
                const normalizedUserId = typeof userId === "string" ? userId : userId.toString();
                const comments = await commentsCollection.find({ userId: new mongodb_1.ObjectId(normalizedUserId) }).toArray();
                const response = await Promise.all(comments.map(buildCommentResponse));
                res.json(response);
            }
            catch (error) {
                console.error("Error fetching user comments:", error);
                res.status(500).json({ message: "Error fetching user comments" });
            }
        });
        app.get("/comments/:ideaId", async (req, res) => {
            try {
                const { ideaId } = req.params;
                const comments = await commentsCollection.find({ ideaId: new mongodb_1.ObjectId(ideaId) }).toArray();
                const response = await Promise.all(comments.map(buildCommentResponse));
                res.json(response);
            }
            catch (error) {
                console.error("Error fetching idea comments:", error);
                res.status(500).json({ message: "Error fetching idea comments" });
            }
        });
        app.delete("/comments/:commentId", verifyToken, async (req, res) => {
            try {
                const { commentId } = req.params;
                const comment = await commentsCollection.findOne({ _id: new mongodb_1.ObjectId(commentId) });
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
            }
            catch (error) {
                console.error("Error deleting comment:", error);
                res.status(500).json({ message: "Error deleting comment" });
            }
        });
        app.patch("/comments/:commentId", verifyToken, async (req, res) => {
            try {
                const { commentId } = req.params;
                const { text } = req.body;
                if (!text || !String(text).trim()) {
                    return res.status(400).json({ message: "Missing or invalid text" });
                }
                const comment = await commentsCollection.findOne({ _id: new mongodb_1.ObjectId(commentId) });
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
            }
            catch (error) {
                console.error("Error updating comment:", error);
                res.status(500).json({ message: "Error updating comment" });
            }
        });
        console.log("Pinged your deployment. You successfully connected to MongoDB!");
    }
    finally {
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
exports.default = app;
