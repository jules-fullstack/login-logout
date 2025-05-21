import { useState } from "react";
import { Link } from "react-router-dom";
import { useAuth } from "../context/AuthContext.jsx";
import LoadingSpinner from "./LoadingSpinner";

export default function ForgotPassword() {
  const [email, setEmail] = useState("");
  const [isSubmitting, setIsSubmitting] = useState(false);
  const [message, setMessage] = useState("");
  const { forgotPassword, error, setError } = useAuth();

  const handleSubmit = async (e) => {
    e.preventDefault();
    setIsSubmitting(true);
    setMessage("");
    setError("");

    try {
      const success = await forgotPassword(email);
      if (success) {
        setMessage("Password reset link has been sent to your email address.");
      }
    } finally {
      setIsSubmitting(false);
    }
  };

  return (
    <div className="auth-card">
      <h2>Forgot Password</h2>
      <p>
        Enter your email address and we'll send you a link to reset your
        password.
      </p>

      {message && (
        <div className="success-message">
          <p>{message}</p>
          <p>
            <Link to="/login">Return to login</Link>
          </p>
        </div>
      )}

      {!message && (
        <form onSubmit={handleSubmit}>
          <input
            type="email"
            value={email}
            onChange={(e) => setEmail(e.target.value)}
            placeholder="Your email address"
            required
            disabled={isSubmitting}
          />

          {error && <div className="error-message">{error}</div>}

          <button type="submit" disabled={isSubmitting}>
            {isSubmitting ? (
              <>
                <LoadingSpinner size="small" /> Sending...
              </>
            ) : (
              "Send Reset Link"
            )}
          </button>

          <div className="form-footer">
            <p>
              <Link to="/login">Back to Login</Link>
            </p>
          </div>
        </form>
      )}
    </div>
  );
}
