import { useState, useEffect } from "react";
import AuthContext from "./authUtils";
import { authAPI } from "../utils/api";

export function AuthProvider({ children }) {
  const [user, setUser] = useState(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);
  const [pendingOtpVerification, setPendingOtpVerification] = useState(null);

  useEffect(() => {
    const checkAuth = async () => {
      try {
        setLoading(true);
        const res = await authAPI.getUser();
        setUser(res.data);
      } catch (err) {
        console.error("Authentication check failed:", err);
        setUser(null);
      } finally {
        setLoading(false);
      }
    };

    checkAuth();
  }, []);

  useEffect(() => {
    if (!user) return;
    
    const refreshInterval = setInterval(async () => {
      try {
        await authAPI.refreshToken();
      } catch (err) {
        console.error("Token refresh failed:", err);
        setUser(null);
      }
    }, 50 * 60 * 1000); // 50 minutes
    
    return () => clearInterval(refreshInterval);
  }, [user]);

  const login = async (email, password) => {
    setError(null);

    try {
      const res = await authAPI.login(email, password);

      if (res.data.requiresOtp) {
        setPendingOtpVerification({
          userId: res.data.userId,
          email,
        });
        return {
          success: true,
          requiresOtp: true,
          userId: res.data.userId,
          email,
        };
      }

      setUser(res.data.user);
      return { success: true };
    } catch (err) {
      if (err.response?.data?.pendingVerification) {
        setError("Please verify your email before logging in");
        return {
          success: false,
          pendingVerification: true,
          email: err.response.data.email,
        };
      }

      setError(err.response?.data?.msg || "Login failed");
      return { success: false };
    }
  };

  const verifyOtp = async (otp) => {
    setError(null);

    if (!pendingOtpVerification) {
      setError("No pending verification");
      return { success: false };
    }

    try {
      const res = await authAPI.verifyOtp(pendingOtpVerification.userId, otp);
      setUser(res.data.user);
      setPendingOtpVerification(null);

      return { success: true };
    } catch (err) {
      setError(err.response?.data?.msg || "Verification failed");
      return { success: false };
    }
  };

  const resendOtp = async () => {
    setError(null);

    if (!pendingOtpVerification) {
      setError("No pending verification");
      return { success: false };
    }

    try {
      await authAPI.resendOtp(pendingOtpVerification.userId);
      return { success: true };
    } catch (err) {
      setError(err.response?.data?.msg || "Failed to resend verification code");
      return { success: false };
    }
  };

  const logout = async () => {
    setError(null);
    
    try {
      await authAPI.logout();
    } catch (err) {
      console.error("Logout error:", err);
    }
    
    setUser(null);
  };

  const signup = async (name, email, password) => {
    setError(null);

    try {
      const res = await authAPI.signup(name, email, password);

      return {
        success: true,
        data: res.data,
      };
    } catch (err) {
      setError(err.response?.data?.msg || "Signup failed");
      return {
        success: false,
        error: err.response?.data,
      };
    }
  };

  const verifyEmail = async (token) => {
    setError(null);

    const processedTokens = JSON.parse(
      localStorage.getItem("processedVerificationTokens") || "[]"
    );
    if (processedTokens.includes(token)) {
      return {
        success: true,
        alreadyVerified: true,
        data: { msg: "Email already verified" },
      };
    }

    try {
      const res = await authAPI.verifyEmail(token);

      processedTokens.push(token);
      localStorage.setItem(
        "processedVerificationTokens",
        JSON.stringify(processedTokens)
      );

      setUser(res.data.user);

      return {
        success: true,
        data: res.data,
      };
    } catch (err) {
      if (
        err.response?.data?.alreadyVerified ||
        err.response?.data?.msg?.includes("already verified") ||
        err.response?.data?.msg?.includes("already been used")
      ) {
        return {
          success: true,
          alreadyVerified: true,
          data: err.response.data,
        };
      }

      console.error(
        "Email verification error:",
        err.response?.data || err.message
      );

      const errorMsg = err.response?.data?.msg || "Email verification failed";
      setError(errorMsg);

      return {
        success: false,
        error: err.response?.data || { msg: errorMsg },
      };
    }
  };

  const resendVerification = async (email) => {
    setError(null);

    try {
      const res = await authAPI.resendVerification(email);

      return {
        success: true,
        data: res.data,
      };
    } catch (err) {
      setError(
        err.response?.data?.msg || "Failed to resend verification email"
      );
      return {
        success: false,
        error: err.response?.data,
      };
    }
  };

  const resetPassword = async (token, password) => {
    setError(null);
    
    try {
      const res = await authAPI.resetPassword(token, password);
      
      setUser(res.data.user);
      
      return { success: true };
    } catch (err) {
      const errorMessage = err.response?.data?.msg || "Failed to reset password";
      setError(errorMessage);
      console.error("Password reset error:", errorMessage);
      return { success: false };
    }
  };

  const forgotPassword = async (email) => {
    setError(null);

    try {
      await authAPI.forgotPassword(email);
      return true;
    } catch (err) {
      setError(err.response?.data?.msg || "Failed to send reset email");
      return false;
    }
  };

  const deleteAccount = async () => {
    setError(null);

    try {
      await authAPI.deleteAccount();
      
      setUser(null);

      return true;
    } catch (err) {
      setError(err.response?.data?.msg || "Failed to delete account");
      return false;
    }
  };

  const updateName = async (newName) => {
    setError(null);

    try {
      const res = await authAPI.updateName(newName);

      setUser(res.data);
      return true;
    } catch (err) {
      const errorMsg = err.response?.data?.msg || "Failed to update name";
      setError(errorMsg);
      console.error("Name update error:", errorMsg);
      return false;
    }
  };

  const updatePassword = async (currentPassword, newPassword) => {
    setError(null);

    try {
      await authAPI.updatePassword(currentPassword, newPassword);
      return true;
    } catch (err) {
      const errorMessage =
        err.response?.data?.msg || "Failed to update password";
      setError(errorMessage);
      console.error("Password update error:", errorMessage);
      return false;
    }
  };

  const refreshToken = async () => {
    try {
      await authAPI.refreshToken();
      return true;
    } catch (err) {
      console.error("Manual token refresh failed:", err);
      setUser(null);
      return false;
    }
  };

  const value = {
    user,
    loading,
    error,
    pendingOtpVerification,
    isAuthenticated: !!user,
    login,
    logout,
    signup,
    resetPassword,
    forgotPassword,
    deleteAccount,
    verifyEmail,
    resendVerification,
    verifyOtp,
    resendOtp,
    setError,
    updateName,
    updatePassword,
    refreshToken,
  };

  return <AuthContext.Provider value={value}>{children}</AuthContext.Provider>;
}