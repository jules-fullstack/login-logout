import React, { useState } from "react";
import { useNavigate } from "react-router-dom";
import { useAuth } from "../context/authUtils";
import LoadingSpinner from "./LoadingSpinner";

export default function Home() {
  const { user, loading, logout, deleteAccount, error } = useAuth();
  const [isDeleting, setIsDeleting] = useState(false);
  const [showConfirmation, setShowConfirmation] = useState(false);
  const [postContent, setPostContent] = useState("");
  const navigate = useNavigate();

  const handleLogout = () => {
    logout();
    navigate("/login");
  };

  const handleCancelDelete = () => {
    setShowConfirmation(false);
  };

  const handleConfirmDelete = async () => {
    setIsDeleting(true);
    const success = await deleteAccount();
    if (success) {
      navigate("/login");
    } else {
      setIsDeleting(false);
      setShowConfirmation(false);
    }
  };

  const handlePostSubmit = (e) => {
    e.preventDefault();
    // This is just UI for now, functionality will be implemented later
    alert("Post created! (Functionality coming soon)");
    setPostContent("");
  };

  if (loading || !user) return <LoadingSpinner size="large" />;

  return (
    <div className="dashboard-container">
      {/* Modern Header with User Info */}
      <header className="app-header">
        <div className="user-profile" onClick={() => setShowConfirmation(true)}>
          <div className="avatar">
            {user.name.charAt(0).toUpperCase()}
          </div>
          <div className="user-info">
            <p className="user-name">{user.name}</p>
            <p className="user-email">{user.email}</p>
          </div>
        </div>
      </header>

      <main className="content-area">
        {/* Post Creation Card */}
        <div className="post-creation-card">
          <div className="post-header">
            <div className="mini-avatar">
              {user.name.charAt(0).toUpperCase()}
            </div>
            <span className="post-prompt">What's on your mind, {user.name.split(' ')[0]}?</span>
          </div>
          <form onSubmit={handlePostSubmit} className="post-form">
            <textarea
              placeholder="Share your thoughts..."
              value={postContent}
              onChange={(e) => setPostContent(e.target.value)}
              className="post-textarea"
            />
            <div className="post-actions">
              <button 
                type="submit" 
                className="post-button"
                disabled={!postContent.trim()}
              >
                <span className="button-icon">✨</span>
                <span>Share Post</span>
              </button>
            </div>
          </form>
        </div>

        {/* News Feed with Modern Design */}
        <div className="feed-container">
          <h2 className="feed-title">Recent Posts</h2>
          <div className="empty-feed">
            <div className="empty-feed-icon">📝</div>
            <h3>No posts yet</h3>
            <p>Be the first to share something interesting!</p>
          </div>
        </div>
      </main>

      {/* Modern Delete Account Modal */}
      {showConfirmation && (
        <div className="modal-overlay">
          <div className="modal-card">
            <div className="modal-header">
              <h3>Account Options</h3>
              <button className="close-button" onClick={handleCancelDelete}>×</button>
            </div>
            <div className="modal-content">
              <div className="account-option" onClick={handleLogout}>
                <span className="option-icon">🚪</span>
                <span className="option-text">Log Out</span>
              </div>
              <div className="account-option danger" onClick={handleConfirmDelete}>
                <span className="option-icon">⚠️</span>
                <span className="option-text">Delete Account</span>
              </div>
              <p className="warning-text">
                Deleting your account is permanent and cannot be undone.
              </p>
              {isDeleting && (
                <div className="deleting-indicator">
                  <LoadingSpinner size="small" />
                  <span>Processing request...</span>
                </div>
              )}
              {error && <div className="error-message">{error}</div>}
            </div>
          </div>
        </div>
      )}
    </div>
  );
}