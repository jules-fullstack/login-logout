import { useState, useEffect } from "react";
import { useParams, useNavigate, Link } from "react-router-dom";
import { useAuth } from "../context/authUtils";
import LoadingSpinner from "./LoadingSpinner";

export default function ResetPassword() {
  const [password, setPassword] = useState("");
  const [confirmPassword, setConfirmPassword] = useState("");
  const [isSubmitting, setIsSubmitting] = useState(false);
  const [message, setMessage] = useState("");
  const [validToken, setValidToken] = useState(true);
  const { resetPassword, error, setError } = useAuth();

  const { token } = useParams();
  const navigate = useNavigate();

  useEffect(() => {}, [token]);

  const handleSubmit = async (e) => {
    e.preventDefault();
    setError("");

    if (password !== confirmPassword) {
      return setError("Passwords do not match");
    }

    // Updated password validation to match server schema
    if (password.length < 8) {
      return setError("Password must be at least 8 characters");
    }

    // Check for uppercase, lowercase, and number
    const hasUppercase = /[A-Z]/.test(password);
    const hasLowercase = /[a-z]/.test(password);
    const hasNumber = /[0-9]/.test(password);

    if (!hasUppercase || !hasLowercase || !hasNumber) {
      return setError(
        "Password must contain at least one uppercase letter, one lowercase letter, and one number"
      );
    }

    setIsSubmitting(true);

    try {
      const result = await resetPassword(token, password);

      if (result.success) {
        setMessage("Password has been reset successfully!");
        setTimeout(() => {
          navigate("/");
        }, 2000);
      } else {
        // Check for already used token message
        if (error && error.includes("already been used")) {
          setValidToken(false);
          setError(
            "This reset link has already been used. Please request a new one."
          );
        } else {
          setValidToken(false);
        }
      }
    } finally {
      setIsSubmitting(false);
    }
  };
  if (!validToken) {
    return (
      <div className="auth-card">
        <h2>Invalid or Expired Link</h2>
        <p>
          Your password reset link is invalid or has expired. Please request a
          new one.
        </p>
        <div className="form-footer">
          <Link to="/forgot-password">Request New Reset Link</Link>
        </div>
      </div>
    );
  }

  return (
    <div className="auth-card">
      <h2>Reset Your Password</h2>

      {message ? (
        <div className="success-message">
          <p>{message}</p>
          <p>Redirecting to your account...</p>
        </div>
      ) : (
        <>
          <p>Please enter your new password below.</p>

          <form onSubmit={handleSubmit}>
            <input
              type="password"
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              placeholder="New Password"
              required
              disabled={isSubmitting}
            />
            <input
              type="password"
              value={confirmPassword}
              onChange={(e) => setConfirmPassword(e.target.value)}
              placeholder="Confirm New Password"
              required
              disabled={isSubmitting}
            />

            {error && <div className="error-message">{error}</div>}
            <div className="password-requirements">
              <h4>Password must:</h4>
              <ul>
                <li className={password.length >= 8 ? "requirement-met" : ""}>
                  Be at least 8 characters long
                </li>
                <li className={/[A-Z]/.test(password) ? "requirement-met" : ""}>
                  Contain at least one uppercase letter
                </li>
                <li className={/[a-z]/.test(password) ? "requirement-met" : ""}>
                  Contain at least one lowercase letter
                </li>
                <li className={/[0-9]/.test(password) ? "requirement-met" : ""}>
                  Contain at least one number
                </li>
              </ul>
            </div>

            <button type="submit" disabled={isSubmitting}>
              {isSubmitting ? (
                <>
                  <LoadingSpinner size="small" /> Resetting...
                </>
              ) : (
                "Reset Password"
              )}
            </button>
          </form>
        </>
      )}
    </div>
  );
}
