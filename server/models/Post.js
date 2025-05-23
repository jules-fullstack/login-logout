const mongoose = require("mongoose");

const PostSchema = new mongoose.Schema({
  content: { type: String, required: true, trim: true },
  user_id: { type: mongoose.Schema.Types.ObjectId, ref: "User", required: true },
}, {
  timestamps: true,
});

module.exports = mongoose.model("Post", PostSchema);