import { createContext, useState, useEffect, useContext } from "react";
import axios from "axios";

const AuthContext = createContext();

export function AuthProvider({ children }) {
  const [user, setUser] = useState(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);

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
  }; // Verify email function
  const verifyEmail = async (token) => {
    setError(null);

    try {
      console.log(`Sending verification request for token: ${token}`);
      const res = await axios.post(
        `http://localhost:5000/api/auth/verify-email/${token}`
      );

      const { token: authToken, user } = res.data;

      // Store token and set auth header
      localStorage.setItem("token", authToken);
      axios.defaults.headers.common["x-auth-token"] = authToken;

      // Update state
      setUser(user);

      console.log("Verification successful:", res.data);
      return {
        success: true,
        data: res.data,
      };
    } catch (err) {
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
  const value = {
    user,
    loading,
    error,
    isAuthenticated: !!user,
    login,
    logout,
    signup,
    resetPassword,
    forgotPassword,
    deleteAccount,
    verifyEmail,
    resendVerification,
    setError,
  };

  return <AuthContext.Provider value={value}>{children}</AuthContext.Provider>;
}

export const useAuth = () => useContext(AuthContext);

export default AuthContext;
