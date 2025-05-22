import React, { useState, useEffect } from "react";
import { useNavigate } from "react-router-dom";
import { useAuth } from "../context/authUtils";
import LoadingSpinner from "./LoadingSpinner";

const Settings = () => {
  const {
    user,
    updateName,
    updatePassword,
    deleteAccount,
    error,
    error: authError,
    setError,
  } = useAuth();
  const navigate = useNavigate();

  const [name, setName] = useState(user?.name || "");
  const [nameUpdating, setNameUpdating] = useState(false);
  const [nameSuccess, setNameSuccess] = useState(false);
  const [nameError, setNameError] = useState("");
  const [isDeleting, setIsDeleting] = useState(false);
  const [showConfirmation, setShowConfirmation] = useState(false);

  const [passwordForm, setPasswordForm] = useState({
    currentPassword: "",
    newPassword: "",
    confirmPassword: "",
  });
  const [passwordUpdating, setPasswordUpdating] = useState(false);
  const [passwordSuccess, setPasswordSuccess] = useState(false);
  const [passwordError, setPasswordError] = useState("");

  useEffect(() => {
    if (authError) {
      if (nameUpdating) {
        setNameError(authError);
        setNameUpdating(false);
      } else if (passwordUpdating) {
        if (authError.includes("incorrect")) {
          setPasswordError("Current password is incorrect");

          setTimeout(() => {
            const inputElement = document.getElementById("currentPassword");
            if (inputElement) {
              inputElement.classList.add("input-error");
              inputElement.focus();
            }
          }, 0);
        } else {
          setPasswordError(authError);
        }
        setPasswordUpdating(false);
      }
    }
  }, [authError, nameUpdating, passwordUpdating]);

  useEffect(() => {
    return () => {
      if (setError) setError(null);
    };
  }, [setError]);

  const handleNameChange = (e) => {
    setName(e.target.value);
    setNameSuccess(false);
    setNameError("");
  };

  const handlePasswordChange = (e) => {
    if (e.target.id === "currentPassword") {
      e.target.classList.remove("input-error");
    }

    setPasswordForm({
      ...passwordForm,
      [e.target.name]: e.target.value,
    });
    setPasswordSuccess(false);

    if (
      passwordError &&
      passwordError.includes("incorrect") &&
      e.target.id === "currentPassword"
    ) {
      setPasswordError("");
    } else {
      setPasswordError("");
    }
  };

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

  const handlePasswordSubmit = async (e) => {
    e.preventDefault();

    const { currentPassword, newPassword, confirmPassword } = passwordForm;

    if (!currentPassword || !newPassword || !confirmPassword) {
      setPasswordError("All fields are required");
      return;
    }

    if (newPassword !== confirmPassword) {
      setPasswordError("New passwords don't match");
      return;
    }

    // Updated password validation to match server schema
    if (newPassword.length < 8) {
      setPasswordError("Password must be at least 8 characters");
      return;
    }

    // Check for uppercase, lowercase, and number
    const hasUppercase = /[A-Z]/.test(newPassword);
    const hasLowercase = /[a-z]/.test(newPassword);
    const hasNumber = /[0-9]/.test(newPassword);

    if (!hasUppercase || !hasLowercase || !hasNumber) {
      setPasswordError(
        "Password must contain at least one uppercase letter, one lowercase letter, and one number"
      );
      return;
    }

    if (newPassword === currentPassword) {
      setPasswordError("New password must be different from current password");
      return;
    }

    setPasswordUpdating(true);
    setPasswordError("");

    try {
      // Update API call to use the authAPI
      const success = await updatePassword(currentPassword, newPassword);
      if (success) {
        setPasswordSuccess(true);
        setPasswordForm({
          currentPassword: "",
          newPassword: "",
          confirmPassword: "",
        });
      }
    } catch (err) {
      if (
        err.response?.status === 400 &&
        err.response?.data?.msg.includes("incorrect")
      ) {
        const inputElement = document.getElementById("currentPassword");
        if (inputElement) {
          inputElement.classList.add("input-error");
          inputElement.focus();
        }
      } else {
        setPasswordError("An error occurred while updating password");
      }
    } finally {
      setPasswordUpdating(false);
    }
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

          {nameError && <div className="error-message">{nameError}</div>}

          {nameSuccess && (
            <div className="success-message">Name updated successfully!</div>
          )}
        </form>
      </div>

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
              className={
                passwordError && passwordError.includes("incorrect")
                  ? "input-error"
                  : ""
              }
            />
            <div className="password-hint">
              <span className="hint-icon">ℹ️</span>
              <span>Make sure this matches your current account password</span>
            </div>
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
            disabled={
              passwordUpdating ||
              !passwordForm.currentPassword ||
              !passwordForm.newPassword ||
              !passwordForm.confirmPassword
            }
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
            <div className="success-message">
              Password changed successfully!
            </div>
          )}
        </form>
      </div>
      {!showConfirmation ? (
        <button
          className="delete-account-btn"
          onClick={handleDeleteAccountClick}
        >
          Delete Account
        </button>
      ) : (
        <div className="delete-confirmation">
          <p>
            Are you sure you want to delete your account? This action cannot be
            undone.
          </p>
          <div className="confirmation-buttons">
            <button
              className="confirm-delete-btn"
              onClick={handleConfirmDelete}
              disabled={isDeleting}
            >
              {isDeleting ? (
                <>
                  <LoadingSpinner size="small" />
                  <span>Deleting...</span>
                </>
              ) : (
                <span>Yes, Delete My Account</span>
              )}
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
};

export default Settings;
