import { useState, useEffect } from "react";
import axios from "axios";
import AuthContext from "./authUtils";

export function AuthProvider({ children }) {
  const [user, setUser] = useState(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);
  const [pendingOtpVerification, setPendingOtpVerification] = useState(null);

  // Check if we have a token on initial load
  useEffect(() => {
    const checkAuth = async () => {
      const token = localStorage.getItem("token");

      if (!token) {
        setLoading(false);
        return;
      }

      try {
        // Set default authorization header for all axios requests
        axios.defaults.headers.common["x-auth-token"] = token;

        const res = await axios.get("http://localhost:5000/api/auth/user");
        setUser(res.data);
      } catch (err) {
        console.error("Authentication check failed:", err);
        localStorage.removeItem("token");
        delete axios.defaults.headers.common["x-auth-token"];
      } finally {
        setLoading(false);
      }
    };

    checkAuth();
  }, []);

  // Login function
  const login = async (email, password) => {
    setError(null);

    try {
      const res = await axios.post("http://localhost:5000/api/auth/login", {
        email,
        password,
      });

      // Check if OTP verification is required
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

      const { token, user } = res.data;

      // Store token and set auth header
      localStorage.setItem("token", token);
      axios.defaults.headers.common["x-auth-token"] = token;

      // Update state
      setUser(user);

      return true;
    } catch (err) {
      // Check if this is a verification issue
      if (err.response?.data?.pendingVerification) {
        setError("Please verify your email before logging in");
        return {
          success: false,
          pendingVerification: true,
          email: err.response.data.email,
        };
      }

      setError(err.response?.data?.msg || "Login failed");
      return false;
    }
  };

  // OTP verification function
  const verifyOtp = async (otp) => {
    setError(null);

    if (!pendingOtpVerification) {
      setError("No pending verification");
      return { success: false };
    }

    try {
      const res = await axios.post(
        "http://localhost:5000/api/auth/verify-otp",
        {
          userId: pendingOtpVerification.userId,
          otp,
        }
      );

      const { token, user } = res.data;

      // Store token and set auth header
      localStorage.setItem("token", token);
      axios.defaults.headers.common["x-auth-token"] = token;

      // Update state
      setUser(user);
      setPendingOtpVerification(null);

      return { success: true };
    } catch (err) {
      setError(err.response?.data?.msg || "Verification failed");
      return { success: false };
    }
  };

  // Resend OTP function
  const resendOtp = async () => {
    setError(null);

    if (!pendingOtpVerification) {
      setError("No pending verification");
      return { success: false };
    }

    try {
      await axios.post("http://localhost:5000/api/auth/resend-otp", {
        userId: pendingOtpVerification.userId,
      });

      return { success: true };
    } catch (err) {
      setError(err.response?.data?.msg || "Failed to resend verification code");
      return { success: false };
    }
  };

  // Logout function
  const logout = () => {
    localStorage.removeItem("token");
    delete axios.defaults.headers.common["x-auth-token"];
    setUser(null);
  };

  // Signup function
  const signup = async (name, email, password) => {
    setError(null);

    try {
      const res = await axios.post("http://localhost:5000/api/auth/signup", {
        name,
        email,
        password,
      });

      // Return the response data for handling by the signup component
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

  // Verify email function
  const verifyEmail = async (token) => {
    setError(null);

    // Use a flag to prevent duplicate tokens from being processed
    const processedTokens = JSON.parse(
      localStorage.getItem("processedVerificationTokens") || "[]"
    );
    if (processedTokens.includes(token)) {
      console.log("Token already processed:", token);
      return {
        success: true,
        alreadyVerified: true,
        data: { msg: "Email already verified" },
      };
    }

    try {
      console.log(`Sending verification request for token: ${token}`);
      const res = await axios.post(
        `http://localhost:5000/api/auth/verify-email/${token}`
      );

      console.log("Verification response:", res.data);

      // Mark this token as processed to prevent duplicate requests
      processedTokens.push(token);
      localStorage.setItem(
        "processedVerificationTokens",
        JSON.stringify(processedTokens)
      );

      if (res.data && res.data.token) {
        const { token: authToken, user } = res.data;

        // Store token and set auth header
        localStorage.setItem("token", authToken);
        axios.defaults.headers.common["x-auth-token"] = authToken;

        // Update state
        setUser(user);

        console.log("User authenticated", user);
        return {
          success: true,
          data: res.data,
        };
      } else if (
        res.data.alreadyVerified ||
        (res.data.msg && res.data.msg.includes("already verified"))
      ) {
        return {
          success: true,
          alreadyVerified: true,
          data: res.data,
        };
      } else {
        console.warn("Unexpected response format:", res.data);
        return {
          success: false,
          error: { msg: "Invalid server response" },
        };
      }
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

      // Detailed error logging
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

  // Resend verification email function
  const resendVerification = async (email) => {
    setError(null);

    try {
      const res = await axios.post(
        "http://localhost:5000/api/auth/resend-verification",
        {
          email,
        }
      );

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

  // Reset password function
  const resetPassword = async (token, password) => {
    setError(null);

    try {
      await axios.post(
        `http://localhost:5000/api/auth/reset-password/${token}`,
        {
          password,
        }
      );
      return true;
    } catch (err) {
      setError(err.response?.data?.msg || "Password reset failed");
      return false;
    }
  };

  // Forgot password function
  const forgotPassword = async (email) => {
    setError(null);

    try {
      await axios.post("http://localhost:5000/api/auth/forgot-password", {
        email,
      });
      return true;
    } catch (err) {
      setError(err.response?.data?.msg || "Failed to send reset email");
      return false;
    }
  };

  // Delete account function
  const deleteAccount = async () => {
    setError(null);

    try {
      const token = localStorage.getItem("token");
      if (!token) return false;

      axios.defaults.headers.common["x-auth-token"] = token;
      await axios.delete("http://localhost:5000/api/auth/delete-account");

      // Clear auth data
      localStorage.removeItem("token");
      delete axios.defaults.headers.common["x-auth-token"];
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
      // Make the API request
      const res = await axios.put(
        "http://localhost:5000/api/auth/update-name",
        { name: newName },
        {
          headers: {
            "x-auth-token": localStorage.getItem("token"),
          },
        }
      );

      // Use the response data from the server to update the user
      setUser(res.data);

      return true;
    } catch (err) {
      const errorMsg = err.response?.data?.msg || "Failed to update name";
      setError(errorMsg);
      console.error("Name update error:", errorMsg);
      return false;
    }
  };

  // Improve updatePassword function with better error handling
  const updatePassword = async (currentPassword, newPassword) => {
    setError(null);

    try {
      await axios.put(
        "http://localhost:5000/api/auth/update-password",
        { currentPassword, newPassword },
        {
          headers: {
            "x-auth-token": localStorage.getItem("token"),
          },
        }
      );
      return true;
    } catch (err) {
      // Get the exact error message from the server
      const errorMessage =
        err.response?.data?.msg || "Failed to update password";
      setError(errorMessage);
      console.error("Password update error:", errorMessage);
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
    updateName, // Add this
    updatePassword,
  };

  return <AuthContext.Provider value={value}>{children}</AuthContext.Provider>;
}
