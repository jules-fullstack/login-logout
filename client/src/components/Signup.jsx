import { useState } from "react";
import { Link } from "react-router-dom";
import { useAuth } from "../context/AuthContext.jsx";
import LoadingSpinner from "./LoadingSpinner";

export default function Signup() {
  const [form, setForm] = useState({ name: "", email: "", password: "" });
  const [isLoading, setIsLoading] = useState(false);
  const [verificationPending, setVerificationPending] = useState(false);
  const [verificationEmail, setVerificationEmail] = useState("");
  const { signup, error, setError } = useAuth();

  const onChange = (e) => setForm({ ...form, [e.target.name]: e.target.value });

  const onSubmit = async (e) => {
    e.preventDefault();
    setError("");
    setIsLoading(true);

    try {
      const result = await signup(form.name, form.email, form.password);

      if (result.success) {
        // Show verification pending screen
        setVerificationPending(true);
        setVerificationEmail(form.email);
      }

      setIsLoading(false);
    } catch (err) {
      console.error("Signup failed:", err);
      setIsLoading(false);
    }
  };

  return (
    <div className="auth-card">
      {verificationPending ? (
        <div className="verification-pending">
          <h2>Verify Your Email</h2>
          <div className="success-message">
            <p>
              Thanks for signing up! We've sent a verification email to:
              <br />
              <strong>{verificationEmail}</strong>
            </p>
            <p>
              Please check your inbox and click the verification link to
              complete your registration.
            </p>
          </div>

          <p>
            Once verified, you'll be able to log in and access your account.
          </p>

          <div className="form-footer">
            <p>
              Already verified? <Link to="/login">Log In</Link>
            </p>
          </div>
        </div>
      ) : (
        <>
          <h2>Create Account</h2>
          <form onSubmit={onSubmit}>
            <input
              name="name"
              placeholder="Full name"
              onChange={onChange}
              required
              disabled={isLoading}
            />
            <input
              name="email"
              placeholder="Email address"
              type="email"
              onChange={onChange}
              required
              disabled={isLoading}
            />
            <input
              name="password"
              placeholder="Password"
              type="password"
              onChange={onChange}
              required
              disabled={isLoading}
            />
            {error && <div className="error-message">{error}</div>}
            <button type="submit" disabled={isLoading}>
              {isLoading ? (
                <>
                  <LoadingSpinner size="small" /> Creating Account...
                </>
              ) : (
                "Sign Up"
              )}
            </button>
          </form>
          <div className="form-footer">
            <p>
              Already have an account? <Link to="/login">Log In</Link>
            </p>
          </div>
        </>
      )}
    </div>
  );
}
