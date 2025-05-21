import React from "react";
import { useNavigate } from "react-router-dom";
import { useAuth } from "../context/AuthContext.jsx";
import LoadingSpinner from "./LoadingSpinner";

export default function Home() {
  const { user, loading, logout } = useAuth();
  const navigate = useNavigate();

  const handleLogout = () => {
    logout();
    navigate("/login");
  };

  if (loading || !user) return <LoadingSpinner size="large" />;

  return (
    <div className="profile-container">
      <div className="profile-header">
        <h1>Welcome, {user.name}!</h1>
      </div>
      <div className="profile-info">
        <p>Your email: {user.email}</p>
      </div>
      <button onClick={handleLogout}>Log Out</button>
    </div>
  );
}
