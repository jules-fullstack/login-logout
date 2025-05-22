import React, { useState } from "react";
import { useNavigate } from "react-router-dom";
import { useAuth } from "../context/authUtils";
import LoadingSpinner from "./LoadingSpinner";

export default function Home() {
  const { user, loading, logout, deleteAccount, error } = useAuth();
  const [isDeleting, setIsDeleting] = useState(false);
  const [showConfirmation, setShowConfirmation] = useState(false);
  const navigate = useNavigate();

  const handleLogout = () => {
    logout();
    navigate("/login");
  };

  const handleDeleteAccountClick = () => {
    setShowConfirmation(true);
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

  if (loading || !user) return <LoadingSpinner size="large" />;

  return (
    <div className="profile-container">
      <div className="profile-header">
        <h1>Welcome, {user.name}!</h1>
      </div>
      <div className="profile-info">
        <p>Your email: {user.email}</p>
      </div>
      <button onClick={handleLogout}>Log Out</button>
      
      {!showConfirmation ? (
        <button className="delete-account-btn" onClick={handleDeleteAccountClick}>
          Delete Account
        </button>
      ) : (
        <div className="delete-confirmation">
          <p>Are you sure you want to delete your account? This action cannot be undone.</p>
          <div className="confirmation-buttons">
            <button 
              className="confirm-delete-btn" 
              onClick={handleConfirmDelete}
              disabled={isDeleting}
            >
              {isDeleting ? <><LoadingSpinner size="small" /> Deleting...</> : "Yes, Delete My Account"}
            </button>
            <button 
              className="cancel-btn" 
              onClick={handleCancelDelete}
              disabled={isDeleting}
            >
              Cancel
            </button>
          </div>
          {error && <div className="error-message">{error}</div>}
        </div>
      )}
    </div>
  );
}
