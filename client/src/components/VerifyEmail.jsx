import { useState, useEffect } from "react";
import { useParams, Link, useNavigate } from "react-router-dom";
import { useAuth } from "../context/AuthContext.jsx";
import LoadingSpinner from "./LoadingSpinner";

export default function VerifyEmail() {
  const { token } = useParams();
  const [verifying, setVerifying] = useState(true);
  const [success, setSuccess] = useState(false);
  const [error, setError] = useState("");
  const { verifyEmail } = useAuth();
  const navigate = useNavigate();
  
  useEffect(() => {
    let isMounted = true;
    
    const doVerify = async () => {
      if (!token) {
        if (isMounted) {
          setError("Invalid verification link");
          setVerifying(false);
        }
        return;
      }      try {
        console.log("Starting verification with token:", token);
        const result = await verifyEmail(token);
        console.log("Verification result:", result);

        if (isMounted) {
          if (result.success) {
            setSuccess(true);
            // Auto navigate to home after successful verification
            setTimeout(() => {
              navigate("/");
            }, 3000);
          } else {
            console.log("Verification failed with error:", result.error);
            setError(result.error?.msg || "Verification failed");
          }
        }
      } catch (err) {
        console.error("Verification error:", err);
        if (isMounted) {
          setError(err.message || "An error occurred during verification");
        }
      } finally {
        // Add a small delay before showing the result to prevent flashing error messages
        if (isMounted) {
          setTimeout(() => {
            setVerifying(false);
          }, 1000);
        }
      }
    };

    doVerify();
    
    return () => {
      isMounted = false;
    };
  }, [token, verifyEmail, navigate]);
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
              <p>The verification link may be invalid or expired.</p>
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
