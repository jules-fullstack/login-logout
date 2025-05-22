import { useState, useEffect, useRef } from "react";
import { useParams, Link, useNavigate } from "react-router-dom";
import { useAuth } from "../context/authUtils";
import LoadingSpinner from "./LoadingSpinner";

export default function VerifyEmail() {
  const { token } = useParams();
  const [verifying, setVerifying] = useState(true);
  const [success, setSuccess] = useState(false);
  const [error, setError] = useState("");
  const verificationAttemptedRef = useRef(false);
  const navigationAttemptedRef = useRef(false);
  const { verifyEmail, user } = useAuth();
  const navigate = useNavigate();

  // Handle redirection to home page
  useEffect(() => {
    // Only execute this effect when success becomes true
    if (success && !navigationAttemptedRef.current) {
      navigationAttemptedRef.current = true;
      const timer = setTimeout(() => {
        navigate("/", { replace: true });
      }, 2000);

      return () => clearTimeout(timer);
    }
  }, [success, navigate]);

  // Main verification effect
  useEffect(() => {
    if (verificationAttemptedRef.current) return;

    let isMounted = true;
    const controller = new AbortController();

    // If user is already logged in, show success and end
    if (user) {
      setSuccess(true);
      setVerifying(false);
      return;
    }

    // Check if we've already verified this token before
    const verificationId = localStorage.getItem("verificationId");
    if (verificationId === token) {
      setSuccess(true);
      setVerifying(false);
      return;
    }

    const doVerify = async () => {
      if (!token) {
        if (isMounted) {
          setVerifying(false);
          setError("Invalid verification link");
        }
        return;
      }

      try {
        verificationAttemptedRef.current = true;

        const result = await verifyEmail(token);

        if (!isMounted) return;

        if (result.success) {
          localStorage.setItem("verificationId", token);
          setSuccess(true);
          setVerifying(false);
        } else {
          setError(result.error?.msg || "Verification failed");
          setVerifying(false);
        }
      } catch (err) {
        console.error("Verification error:", err);
        if (isMounted) {
          setError(err.message || "An error occurred during verification");
          setVerifying(false);
        }
      }
    };

    doVerify();

    return () => {
      isMounted = false;
      controller.abort();
    };
  }, [token, verifyEmail, user]);

  // Render the component
  return (
    <div className="auth-card">
      <h2>Email Verification</h2>
      {verifying ? (
        <div className="verifying">
          <LoadingSpinner />
          <p>Verifying your email...</p>
        </div>
      ) : success ? (
        <div className="verification-success">
          <div className="success-message">
            <p>Your email has been successfully verified!</p>
            <p>You are now logged in and will be redirected to your account.</p>
          </div>
          <div className="form-footer">
            <p>
              <Link to="/">Go to Home</Link>
            </p>
          </div>
        </div>
      ) : (
        <div className="verification-failed">
          <div className="error-message">
            <p>{error || "Verification failed"}</p>
            {error && error.includes("expired") ? (
              <p>
                You can request a new verification link from the login page.
              </p>
            ) : (
              <p>
                If you've already verified your email, please try{" "}
                <Link to="/login">logging in</Link> instead.
              </p>
            )}
          </div>
          <div className="form-footer">
            <p>
              <Link to="/login">Go to Login</Link>
            </p>
          </div>
        </div>
      )}
    </div>
  );
}
