import { useState, useEffect } from "react";
import { Link } from "react-router-dom";
import { useAuth } from "../context/authUtils";
import LoadingSpinner from "./LoadingSpinner";

export default function Signup() {
  const [form, setForm] = useState({ name: "", email: "", password: "" });
  const [password, setPassword] = useState("");
  const [confirmPassword, setConfirmPassword] = useState("");
  const [isLoading, setIsLoading] = useState(false);
  const [verificationPending, setVerificationPending] = useState(false);
  const [verificationEmail, setVerificationEmail] = useState("");
  const [localError, setLocalError] = useState("");
  const { signup, setError } = useAuth();

  useEffect(() => {
    setError("");
  }, [setError]);

  const onChange = (e) => setForm({ ...form, [e.target.name]: e.target.value });

  const onSubmit = async (e) => {
    e.preventDefault();
    setLocalError("");
    setError("");

    if (password !== confirmPassword) {
      return setLocalError("Passwords do not match");
    }

    // Updated password validation to match server schema
    if (password.length < 8) {
      return setLocalError("Password must be at least 8 characters");
    }

    // Check for uppercase, lowercase, and number
    const hasUppercase = /[A-Z]/.test(password);
    const hasLowercase = /[a-z]/.test(password);
    const hasNumber = /[0-9]/.test(password);

    if (!hasUppercase || !hasLowercase || !hasNumber) {
      return setLocalError(
        "Password must contain at least one uppercase letter, one lowercase letter, and one number"
      );
    }

    // Update form object to include password
    form.password = password;

    setIsLoading(true);

    try {
      const result = await signup(form.name, form.email, form.password);

      if (result.success) {
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
              onChange={(e) => setPassword(e.target.value)}
              required
              disabled={isLoading}
            />

            <input
              name="confirmPassword"
              placeholder="Confirm Password"
              type="password"
              onChange={(e) => setConfirmPassword(e.target.value)}
              required
              disabled={isLoading}
            />
            {localError && <div className="error-message">{localError}</div>}
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
