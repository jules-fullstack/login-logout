import React, { useState, useEffect, useCallback } from "react";
import { useNavigate } from "react-router-dom";
import { useAuth } from "../context/authUtils";
import LoadingSpinner from "./LoadingSpinner";
import { postsAPI, setAuthToken } from "../utils/api";

export default function Home() {
  const { user, loading, logout, deleteAccount, error } = useAuth();
  const [isDeleting, setIsDeleting] = useState(false);
  const [showConfirmation, setShowConfirmation] = useState(false);
  const [postContent, setPostContent] = useState("");
  const [posts, setPosts] = useState([]);
  const [postsLoading, setPostsLoading] = useState(false);
  const [creatingPost, setCreatingPost] = useState(false);
  const [postError, setPostError] = useState(null);
  const [pagination, setPagination] = useState({
    page: 1,
    totalPages: 1,
  });
  const navigate = useNavigate();


  const fetchPosts = useCallback(async () => {
    try {
      setPostsLoading(true);
      const res = await postsAPI.getPosts(pagination.page);
      setPosts(prevPosts => {
        // If we're on page 1, replace all posts
        // Otherwise append new posts to existing ones
        if (pagination.page === 1) {
          return res.data.posts;
        } else {
          return [...prevPosts, ...res.data.posts];
        }
      });
      setPagination(res.data.pagination);
    } catch (err) {
      console.error("Error fetching posts:", err);
      setPostError("Failed to load posts. Please try again.");
    } finally {
      setPostsLoading(false);
    }
  }, [pagination.page]);

  // Fetch posts when component mounts or page changes
  useEffect(() => {
    fetchPosts();
  }, [fetchPosts]); // fetchPosts is stable now, so this is safe


  
  const handlePostSubmit = async (e) => {
    e.preventDefault();
    if (!postContent.trim()) return;
    
    try {
      setCreatingPost(true);
      setPostError(null);
      
      const res = await postsAPI.createPost(postContent);
      
      // Add the new post to the top of the list
      setPosts(prevPosts => [res.data, ...prevPosts]);
      setPostContent("");
    } catch (err) {
      console.error("Error creating post:", err);
      setPostError("Failed to create post. Please try again.");
    } finally {
      setCreatingPost(false);
    }
  };

  const handleLogout = () => {
    // Clear auth token from localStorage
    setAuthToken(null);
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
      setAuthToken(null);
      navigate("/login");
    } else {
      setIsDeleting(false);
      setShowConfirmation(false);
    }
  };

  const handleLoadMore = () => {
    if (pagination.page < pagination.totalPages) {
      setPagination(prev => ({ ...prev, page: prev.page + 1 }));
    }
  };

  if (loading || !user) return <LoadingSpinner size="large" />;

  // Format date for display
  const formatDate = (dateString) => {
    const date = new Date(dateString);
    return date.toLocaleString('en-US', { 
      month: 'short', 
      day: 'numeric',
      hour: '2-digit', 
      minute: '2-digit'
    });
  };

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
              disabled={creatingPost}
            />
            {postError && <div className="post-error">{postError}</div>}
            <div className="post-actions">
              <button 
                type="submit" 
                className="post-button"
                disabled={!postContent.trim() || creatingPost}
              >
                {creatingPost ? (
                  <>
                    <div className="loading-spinner loading-spinner-small">
                      <div className="spinner"></div>
                    </div>
                    <span>Posting...</span>
                  </>
                ) : (
                  <>
                    <span className="button-icon">✨</span>
                    <span>Share Post</span>
                  </>
                )}
              </button>
            </div>
          </form>
        </div>

        {/* News Feed with Modern Design */}
        <div className="feed-container">
          <h2 className="feed-title">Recent Posts</h2>
          
          {postsLoading && posts.length === 0 ? (
            <div className="feed-loading">
              <LoadingSpinner size="medium" />
              <p>Loading posts...</p>
            </div>
          ) : posts.length === 0 ? (
            <div className="empty-feed">
              <div className="empty-feed-icon">📝</div>
              <h3>No posts yet</h3>
              <p>Be the first to share something interesting!</p>
            </div>
          ) : (
            <>
              <div className="posts-list">
                {posts.map(post => (
                  <div key={post._id} className="post-card">
                    <div className="post-card-header">
                      <div className="mini-avatar">
                        {post.user_id.name.charAt(0).toUpperCase()}
                      </div>
                      <div className="post-info">
                        <div className="post-author">{post.user_id.name}</div>
                        <div className="post-time">{formatDate(post.createdAt)}</div>
                      </div>
                    </div>
                    <div className="post-content">{post.content}</div>
                  </div>
                ))}
              </div>
              
              {pagination.page < pagination.totalPages && (
                <button 
                  onClick={handleLoadMore} 
                  className="load-more-button"
                  disabled={postsLoading}
                >
                  {postsLoading ? 'Loading...' : 'Load More'}
                </button>
              )}
            </>
          )}
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