import { useState, useEffect } from "react";
import { useParams, useNavigate, Link } from "react-router-dom";
import { useAuth } from "../context/AuthContext.jsx";
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

  useEffect(() => {
    // We could validate the token on component mount
    // but for simplicity, we'll just check it when submitting
  }, [token]);

  const handleSubmit = async (e) => {
    e.preventDefault();
    setError("");

    if (password !== confirmPassword) {
      return setError("Passwords do not match");
    }

    if (password.length < 6) {
      return setError("Password must be at least 6 characters");
    }

    setIsSubmitting(true);

    try {
      const success = await resetPassword(token, password);

      if (success) {
        setMessage("Password has been reset successfully!");
        // Redirect to login after 3 seconds
        setTimeout(() => {
          navigate("/login");
        }, 3000);
      } else {
        setValidToken(false);
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
          <p>Redirecting to login page...</p>
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
