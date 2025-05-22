import { useState, useEffect, useRef } from "react";
import { useNavigate } from "react-router-dom";
import { useAuth } from "../context/authUtils";
import LoadingSpinner from "./LoadingSpinner";

export default function OtpVerification() {
  const [otp, setOtp] = useState("");
  const [timeLeft, setTimeLeft] = useState(600);
  const [isLoading, setIsLoading] = useState(false);
  const [resendLoading, setResendLoading] = useState(false);
  const [resendSuccess, setResendSuccess] = useState(false);
  const { verifyOtp, resendOtp, error, pendingOtpVerification } = useAuth();
  const navigate = useNavigate();
  const timerRef = useRef(null);

  useEffect(() => {
    if (!pendingOtpVerification) {
      navigate("/login");
      return;
    }

    timerRef.current = setInterval(() => {
      setTimeLeft(prevTime => {
        if (prevTime <= 1) {
          clearInterval(timerRef.current);
          return 0;
        }
        return prevTime - 1;
      });
    }, 1000);

    return () => {
      clearInterval(timerRef.current);
    };
  }, [pendingOtpVerification, navigate]);

  const formatTime = (seconds) => {
    const mins = Math.floor(seconds / 60);
    const secs = seconds % 60;
    return `${mins}:${secs < 10 ? '0' : ''}${secs}`;
  };

  const handleResendOtp = async () => {
    setResendLoading(true);
    setResendSuccess(false);
    
    const result = await resendOtp();
    
    if (result.success) {
      setResendSuccess(true);
      setTimeLeft(600);
      
      clearInterval(timerRef.current);
      timerRef.current = setInterval(() => {
        setTimeLeft(prevTime => {
          if (prevTime <= 1) {
            clearInterval(timerRef.current);
            return 0;
          }
          return prevTime - 1;
        });
      }, 1000);
    }
    
    setResendLoading(false);
  };

  const handleSubmit = async (e) => {
    e.preventDefault();
    setIsLoading(true);

    const result = await verifyOtp(otp);
    
    if (result.success) {
      navigate("/");
    }
    
    setIsLoading(false);
  };

  const handleChange = (e) => {
    const value = e.target.value.replace(/[^0-9]/g, '');
    if (value.length <= 6) {
      setOtp(value);
    }
  };

  return (
    <div className="auth-card">
      <h2>Verification Required</h2>
      
      <p>
        For your security, we've sent a 6-digit verification code to{" "}
        <strong>{pendingOtpVerification?.email}</strong>
      </p>

      <div className="otp-timer">
        <p>Code expires in: <span className={timeLeft < 60 ? "expiring" : ""}>{formatTime(timeLeft)}</span></p>
      </div>
      
      <form onSubmit={handleSubmit}>
        <div className="otp-input-container">
          <input
            type="text"
            placeholder="Enter 6-digit code"
            value={otp}
            onChange={handleChange}
            className="otp-input"
            maxLength="6"
            disabled={isLoading}
            required
          />
        </div>

        {error && <div className="error-message">{error}</div>}
        {resendSuccess && <div className="success-message">Verification code resent successfully!</div>}
        
        <button type="submit" disabled={isLoading || otp.length !== 6}>
          {isLoading ? (
            <>
              <LoadingSpinner size="small" /> Verifying...
            </>
          ) : (
            "Verify"
          )}
        </button>
      </form>

      <div className="form-footer">
        <p>
          Didn't receive the code?{" "}
          <button 
            onClick={handleResendOtp} 
            disabled={resendLoading || timeLeft > 540}
            className="link-button"
          >
            {resendLoading ? (
              <>
                <LoadingSpinner size="small" /> Resending...
              </>
            ) : timeLeft > 540 ? (
              `Resend available in ${formatTime(timeLeft - 540)}`
            ) : (
              "Resend Code"
            )}
          </button>
        </p>
      </div>
    </div>
  );
}