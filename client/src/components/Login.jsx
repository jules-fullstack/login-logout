import { useState } from "react";
import { useNavigate, Link } from "react-router-dom";
import { useAuth } from "../context/authUtils";
import LoadingSpinner from "./LoadingSpinner";

export default function Login() {
  const [form, setForm] = useState({ email: "", password: "" });
  const [isLoading, setIsLoading] = useState(false);
  const [pendingVerification, setPendingVerification] = useState(false);
  const [verificationEmail, setVerificationEmail] = useState("");
  const [resendingVerification, setResendingVerification] = useState(false);
  const [resendSuccess, setResendSuccess] = useState(false);
  const { login, error, setError, resendVerification } = useAuth();
  const navigate = useNavigate();
  const onChange = (e) => setForm({ ...form, [e.target.name]: e.target.value });

  const handleResendVerification = async () => {
    setResendingVerification(true);
    setResendSuccess(false);
    setError("");

    try {
      const result = await resendVerification(verificationEmail);
      if (result.success) {
        setResendSuccess(true);
      }
    } catch (err) {
      console.error("Failed to resend verification email", err);
    } finally {
      setResendingVerification(false);
    }
  };
  
  const onSubmit = async (e) => {
    e.preventDefault();
    setError("");
    setIsLoading(true);
    setPendingVerification(false);

    try {
      const result = await login(form.email, form.password);

      if (result.success) {
        if (result.requiresOtp) {
          // Redirect to OTP verification page
          navigate("/verify-otp");
        } else {
          // Successfully logged in without OTP
          navigate("/");
        }
      } else if (result.pendingVerification) {
        // Email verification required
        setPendingVerification(true);
        setVerificationEmail(result.email);
      }

      setIsLoading(false);
    } catch (err) {
      console.error("Login failed:", err);
      setIsLoading(false);
    }
  };
  
  return (
    <div className="auth-card">
      {pendingVerification ? (
        <div className="verification-pending">
          <h2>Email Verification Required</h2>
          <p>
            Your account requires email verification. Please check your inbox
            and click the verification link in the email we sent to{" "}
            <strong>{verificationEmail}</strong>.
          </p>
          <div className="resend-verification">
            <p>Didn't receive the email?</p>
            <button
              onClick={handleResendVerification}
              disabled={resendingVerification}
              className="secondary-button"
            >
              {resendingVerification ? (
                <>
                  <LoadingSpinner size="small" /> Resending...
                </>
              ) : (
                "Resend Verification Email"
              )}
            </button>
            {resendSuccess && (
              <div className="success-message">
                Verification email resent successfully. Please check your inbox.
              </div>
            )}
          </div>
          <div className="form-footer">
            <p>
              <Link to="/login" onClick={() => setPendingVerification(false)}>
                Back to Login
              </Link>
            </p>
          </div>
        </div>
      ) : (
        <>
          <h2>Welcome Back</h2>
          <form onSubmit={onSubmit}>
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
            <div className="forgot-password">
              <Link to="/forgot-password">Forgot Password?</Link>
            </div>
            <button type="submit" disabled={isLoading}>
              {isLoading ? (
                <>
                  <LoadingSpinner size="small" /> Logging in...
                </>
              ) : (
                "Log In"
              )}
            </button>
          </form>
          <div className="form-footer">
            <p>
              No account? <Link to="/signup">Sign Up</Link>
            </p>
          </div>
        </>
      )}
    </div>
  );
}