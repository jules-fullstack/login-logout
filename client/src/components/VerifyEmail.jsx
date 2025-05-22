import { useState, useEffect } from "react";
import { useParams, Link, useNavigate } from "react-router-dom";
import { useAuth } from "../context/authUtils";
import LoadingSpinner from "./LoadingSpinner";

export default function VerifyEmail() {
  const { token } = useParams();
  const [verifying, setVerifying] = useState(true);
  const [success, setSuccess] = useState(false);
  const [error, setError] = useState("");
  const [verificationAttempted, setVerificationAttempted] = useState(false);
  const { verifyEmail, user } = useAuth();
  const navigate = useNavigate();

 useEffect(() => {
    // Add a flag to track if we should make the verification request
    let shouldVerify = true;
    
    // If already verified through login or page is refreshed after successful verification
    if (user) {
      setSuccess(true);
      setVerifying(false);
      shouldVerify = false;
    }

    // Check if this token was already verified in this session
    const verificationId = localStorage.getItem("verificationId");
    if (verificationId === token) {
      setSuccess(true);
      setVerifying(false);
      shouldVerify = false;
    }
    
    // Only attempt verification once per component mount
    if (verificationAttempted) {
      shouldVerify = false;
    }

    // Create an AbortController for cleanup
    const controller = new AbortController();
    let isMounted = true;

    const doVerify = async () => {
      if (!token || !shouldVerify) {
        if (isMounted) {
          setVerifying(false);
          if (!token) {
            setError("Invalid verification link");
          }
        }
        return;
      }
      
      try {
        setVerificationAttempted(true);
        console.log("Starting verification with token:", token);
        
        // Use the abort controller with the request
        const result = await verifyEmail(token);
        console.log("Verification result:", result);

        if (!isMounted) return;

        if (result.success) {
          // Store this token as verified to prevent repeated attempts
          localStorage.setItem("verificationId", token);
          setSuccess(true);
          
          // Auto navigate to home after successful verification
          setTimeout(() => {
            if (isMounted) {
              navigate("/");
            }
          }, 3000);
        } else if (result.alreadyVerified) {
          setSuccess(true);
        } else {
          setError(result.error?.msg || "Verification failed");
        }
      } catch (err) {
        console.error("Verification error:", err);
        if (isMounted) {
          setError(err.message || "An error occurred during verification");
        }
      } finally {
        if (isMounted) {
          // Short delay to prevent flashing states
          setTimeout(() => {
            setVerifying(false);
          }, 800);
        }
      }
    };

    if (shouldVerify) {
      doVerify();
    }
    
    return () => {
      isMounted = false;
      controller.abort(); // Cancel any in-flight requests when component unmounts
    };
  }, [token, verifyEmail, navigate, user, verificationAttempted]);

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
                If you've already verified your email, please try <Link to="/login">logging in</Link> instead.
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