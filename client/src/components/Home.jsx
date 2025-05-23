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
  // States for edit/delete functionality
  const [editingPostId, setEditingPostId] = useState(null);
  const [editContent, setEditContent] = useState("");
  const [updatingPost, setUpdatingPost] = useState(false);
  const [deletingPostId, setDeletingPostId] = useState(null);
  const [showDeleteConfirmation, setShowDeleteConfirmation] = useState(false);
  
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

  // Handle starting edit mode for a post
  const handleEditPost = (post) => {
    setEditingPostId(post._id);
    setEditContent(post.content);
  };

  // Handle canceling edit mode
  const handleCancelEdit = () => {
    setEditingPostId(null);
    setEditContent("");
  };

  // Handle saving edited post
  const handleSaveEdit = async (postId) => {
    if (!editContent.trim()) return;
    
    try {
      setUpdatingPost(true);
      
      const res = await postsAPI.updatePost(postId, editContent);
      
      // Update the post in the state
      setPosts(prevPosts => 
        prevPosts.map(post => 
          post._id === postId ? res.data : post
        )
      );
      
      // Exit edit mode
      setEditingPostId(null);
      setEditContent("");
    } catch (err) {
      console.error("Error updating post:", err);
      setPostError("Failed to update post. Please try again.");
    } finally {
      setUpdatingPost(false);
    }
  };

  // Handle showing delete confirmation
  const handleDeletePrompt = (postId) => {
    setDeletingPostId(postId);
    setShowDeleteConfirmation(true);
  };

  // Handle canceling delete
  const handleCancelDelete = () => {
    setShowConfirmation(false);
    setShowDeleteConfirmation(false);
    setDeletingPostId(null);
  };

  // Handle confirming post delete
  const handleConfirmPostDelete = async () => {
    try {
      await postsAPI.deletePost(deletingPostId);
      
      // Remove the post from state
      setPosts(prevPosts => 
        prevPosts.filter(post => post._id !== deletingPostId)
      );
      
      // Close the confirmation dialog
      setShowDeleteConfirmation(false);
      setDeletingPostId(null);
    } catch (err) {
      console.error("Error deleting post:", err);
      setPostError("Failed to delete post. Please try again.");
    }
  };

  const handleLogout = () => {
    // Clear auth token from localStorage
    setAuthToken(null);
    logout();
    navigate("/login");
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

  // Check if current user is the post owner
  const isPostOwner = (post) => {
    return post.user_id._id === user.id;
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
                      
                      {/* Post Actions (Edit/Delete) for post owner */}
                      {isPostOwner(post) && (
                        <div className="post-actions-menu">
                          <button 
                            className="post-action-btn edit"
                            onClick={() => handleEditPost(post)}
                            title="Edit post"
                          >
                            ✏️
                          </button>
                          <button 
                            className="post-action-btn delete"
                            onClick={() => handleDeletePrompt(post._id)}
                            title="Delete post"
                          >
                            🗑️
                          </button>
                        </div>
                      )}
                    </div>
                    
                    {/* Show edit form or regular content */}
                    {editingPostId === post._id ? (
                      <div className="post-edit-form">
                        <textarea
                          value={editContent}
                          onChange={(e) => setEditContent(e.target.value)}
                          className="post-edit-textarea"
                          disabled={updatingPost}
                        />
                        <div className="edit-actions">
                          <button 
                            onClick={() => handleSaveEdit(post._id)}
                            className="save-edit-btn"
                            disabled={!editContent.trim() || updatingPost}
                          >
                            {updatingPost ? 'Saving...' : 'Save'}
                          </button>
                          <button 
                            onClick={handleCancelEdit}
                            className="cancel-edit-btn"
                            disabled={updatingPost}
                          >
                            Cancel
                          </button>
                        </div>
                      </div>
                    ) : (
                      <div className="post-content">{post.content}</div>
                    )}
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

      {/* Account Options Modal */}
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

      {/* Delete Post Confirmation Modal */}
      {showDeleteConfirmation && (
        <div className="modal-overlay">
          <div className="modal-card small">
            <div className="modal-header">
              <h3>Delete Post</h3>
              <button className="close-button" onClick={handleCancelDelete}>×</button>
            </div>
            <div className="modal-content">
              <p className="confirmation-message">
                Are you sure you want to delete this post? This action cannot be undone.
              </p>
              <div className="confirmation-actions">
                <button 
                  className="confirm-delete-btn"
                  onClick={handleConfirmPostDelete}
                >
                  Delete
                </button>
                <button 
                  className="cancel-btn"
                  onClick={handleCancelDelete}
                >
                  Cancel
                </button>
              </div>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}