const express = require("express");
const router = express.Router();
const mongoose = require("mongoose");
const Post = require("../models/Post");
const authMiddleware = require("../middleware/auth");

// Apply auth middleware to all routes
router.use(authMiddleware);

// GET /api/posts - Get all posts with pagination
router.get("/", async (req, res) => {
  try {
    const page = parseInt(req.query.page) || 1;
    const limit = parseInt(req.query.limit) || 10;
    const skip = (page - 1) * limit;

    const posts = await Post.find()
      .populate("user_id", "name email")
      .sort({ createdAt: -1 })
      .skip(skip)
      .limit(limit);

    const total = await Post.countDocuments();
    const totalPages = Math.ceil(total / limit);

    res.json({
      posts,
      pagination: {
        page,
        limit,
        total,
        totalPages,
      },
    });
  } catch (err) {
    console.error("Error fetching posts:", err);
    res.status(500).json({ msg: "Server error" });
  }
});

// POST /api/posts - Create a new post
router.post("/", async (req, res) => {
  try {
    const { content } = req.body;
    
    if (!content || content.trim() === "") {
      return res.status(400).json({ msg: "Post content is required" });
    }

    const newPost = new Post({
      content: content.trim(),
      user_id: req.user.id,
    });

    await newPost.save();

    // Populate user info before returning
    const post = await Post.findById(newPost._id).populate(
      "user_id", 
      "name email"
    );

    res.status(201).json(post);
  } catch (err) {
    console.error("Error creating post:", err);
    res.status(500).json({ msg: "Server error" });
  }
});

// PUT /api/posts/:id - Update a post
router.put("/:id", async (req, res) => {
  try {
    const { id } = req.params;
    const { content } = req.body;

    if (!mongoose.Types.ObjectId.isValid(id)) {
      return res.status(400).json({ msg: "Invalid post ID" });
    }

    if (!content || content.trim() === "") {
      return res.status(400).json({ msg: "Post content is required" });
    }

    const post = await Post.findById(id);
    
    if (!post) {
      return res.status(404).json({ msg: "Post not found" });
    }

    // Check if user is the owner of the post - convert both to strings
    if (String(post.user_id) !== String(req.user.id)) {
      return res.status(403).json({ msg: "Not authorized to update this post" });
    }

    post.content = content.trim();
    await post.save();

    const updatedPost = await Post.findById(id).populate(
      "user_id", 
      "name email"
    );

    res.json(updatedPost);
  } catch (err) {
    console.error("Error updating post:", err);
    res.status(500).json({ msg: "Server error" });
  }
});

// DELETE /api/posts/:id - Delete a post
router.delete("/:id", async (req, res) => {
  try {
    const { id } = req.params;

    if (!mongoose.Types.ObjectId.isValid(id)) {
      return res.status(400).json({ msg: "Invalid post ID" });
    }

    const post = await Post.findById(id);
    
    if (!post) {
      return res.status(404).json({ msg: "Post not found" });
    }

    // Check if user is the owner of the post - convert both to strings
    if (String(post.user_id) !== String(req.user.id)) {
      return res.status(403).json({ msg: "Not authorized to delete this post" });
    }

    await Post.deleteOne({ _id: id });

    res.json({ msg: "Post deleted successfully" });
  } catch (err) {
    console.error("Error deleting post:", err);
    res.status(500).json({ msg: "Server error" });
  }
});

module.exports = router;