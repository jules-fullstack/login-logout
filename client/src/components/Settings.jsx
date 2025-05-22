import React, { useState, useEffect } from "react";
import { useAuth } from "../context/authUtils";
import LoadingSpinner from "./LoadingSpinner";

const Settings = () => {
  // Get error from useAuth as well
  const { user, updateName, updatePassword, error: authError, setError } = useAuth();
  
  // Name update state
  const [name, setName] = useState(user?.name || "");
  const [nameUpdating, setNameUpdating] = useState(false);
  const [nameSuccess, setNameSuccess] = useState(false);
  const [nameError, setNameError] = useState("");
  
  // Password update state
  const [passwordForm, setPasswordForm] = useState({
    currentPassword: "",
    newPassword: "",
    confirmPassword: ""
  });
  const [passwordUpdating, setPasswordUpdating] = useState(false);
  const [passwordSuccess, setPasswordSuccess] = useState(false);
  const [passwordError, setPasswordError] = useState("");

  // Sync with auth error
  useEffect(() => {
    if (authError) {
      if (nameUpdating) {
        setNameError(authError);
        setNameUpdating(false);
      } else if (passwordUpdating) {
        setPasswordError(authError);
        setPasswordUpdating(false);
      }
    }
  }, [authError, nameUpdating, passwordUpdating]);

  // Clear auth error when component unmounts
  useEffect(() => {
    return () => {
      if (setError) setError(null);
    };
  }, [setError]);

  // Handle name form input
  const handleNameChange = (e) => {
    setName(e.target.value);
    setNameSuccess(false);
    setNameError("");
  };

  // Handle password form input
  const handlePasswordChange = (e) => {
    setPasswordForm({
      ...passwordForm,
      [e.target.name]: e.target.value
    });
    setPasswordSuccess(false);
    setPasswordError("");
  };

  // Submit name update
  const handleNameSubmit = async (e) => {
    e.preventDefault();
    
    if (!name.trim() || name === user.name) {
      return;
    }
    
    setNameUpdating(true);
    setNameError("");
    
    try {
      const success = await updateName(name);
      if (success) {
        setNameSuccess(true);
      }
    } catch (err) {
      setNameError(err.message || "Failed to update name");
    } finally {
      setNameUpdating(false);
    }
  };

  // Submit password update
  const handlePasswordSubmit = async (e) => {
    e.preventDefault();
    
    const { currentPassword, newPassword, confirmPassword } = passwordForm;
    
    // Basic validation
    if (!currentPassword || !newPassword || !confirmPassword) {
      setPasswordError("All fields are required");
      return;
    }
    
    if (newPassword !== confirmPassword) {
      setPasswordError("New passwords don't match");
      return;
    }
    
    if (newPassword.length < 8) {
      setPasswordError("Password must be at least 8 characters");
      return;
    }
    
    setPasswordUpdating(true);
    setPasswordError("");
    
    try {
      const success = await updatePassword(currentPassword, newPassword);
      if (success) {
        setPasswordSuccess(true);
        setPasswordForm({
          currentPassword: "",
          newPassword: "",
          confirmPassword: ""
        });
      }
    } catch (err) {
      setPasswordError(err.message || "Failed to update password");
    } finally {
      setPasswordUpdating(false);
    }
  };

  // Loading state
  if (!user) return <LoadingSpinner size="large" />;

  return (
    <div className="settings-container">
      <div className="settings-header">
        <h1>Your Settings</h1>
        <div className="settings-icons">
          <span className="settings-icon">🔧</span>
          <span className="settings-icon">⚙️</span>
        </div>
      </div>

      {/* Update Name Section */}
      <div className="settings-section">
        <h2>Update Your Name</h2>
        <form onSubmit={handleNameSubmit} className="settings-form">
          <div className="form-group">
            <label htmlFor="name">Name</label>
            <input
              type="text"
              id="name"
              value={name}
              onChange={handleNameChange}
              disabled={nameUpdating}
            />
          </div>
          
          <button 
            type="submit" 
            disabled={nameUpdating || !name.trim() || name === user.name}
            className="update-button"
          >
            {nameUpdating ? (
              <>
                <LoadingSpinner size="small" />
                <span>Updating...</span>
              </>
            ) : (
              <span>Update Name</span>
            )}
          </button>
          
          {nameError && (
            <div className="error-message">{nameError}</div>
          )}
          
          {nameSuccess && (
            <div className="success-message">Name updated successfully!</div>
          )}
        </form>
      </div>

      {/* Update Password Section */}
      <div className="settings-section">
        <h2>Change Your Password</h2>
        <form onSubmit={handlePasswordSubmit} className="settings-form">
          <div className="form-group">
            <label htmlFor="currentPassword">Current Password</label>
            <input
              type="password"
              id="currentPassword"
              name="currentPassword"
              value={passwordForm.currentPassword}
              onChange={handlePasswordChange}
              disabled={passwordUpdating}
            />
          </div>
          
          <div className="form-group">
            <label htmlFor="newPassword">New Password</label>
            <input
              type="password"
              id="newPassword"
              name="newPassword"
              value={passwordForm.newPassword}
              onChange={handlePasswordChange}
              disabled={passwordUpdating}
            />
          </div>
          
          <div className="form-group">
            <label htmlFor="confirmPassword">Confirm New Password</label>
            <input
              type="password"
              id="confirmPassword"
              name="confirmPassword"
              value={passwordForm.confirmPassword}
              onChange={handlePasswordChange}
              disabled={passwordUpdating}
            />
          </div>
          
          <button 
            type="submit" 
            disabled={passwordUpdating || !passwordForm.currentPassword || !passwordForm.newPassword || !passwordForm.confirmPassword}
            className="update-button"
          >
            {passwordUpdating ? (
              <>
                <LoadingSpinner size="small" />
                <span>Updating...</span>
              </>
            ) : (
              <span>Change Password</span>
            )}
          </button>
          
          {passwordError && (
            <div className="error-message">{passwordError}</div>
          )}
          
          {passwordSuccess && (
            <div className="success-message">Password changed successfully!</div>
          )}
        </form>
      </div>
    </div>
  );
};

export default Settings;