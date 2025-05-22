import React, { useState, useRef, useEffect } from "react";
import { Link, useNavigate } from "react-router-dom";
import { useAuth } from "../context/authUtils";

const Navbar = () => {
  const { user, logout } = useAuth();
  const [showDropdown, setShowDropdown] = useState(false);
  const dropdownRef = useRef(null);
  const navigate = useNavigate();

  const handleLogout = () => {
    setShowDropdown(false);
    logout();
    navigate("/login");
  };

  const handleSettingsClick = () => {
    setShowDropdown(false);
    navigate("/settings");
  };

  useEffect(() => {
    const handleClickOutside = (event) => {
      if (dropdownRef.current && !dropdownRef.current.contains(event.target)) {
        setShowDropdown(false);
      }
    };

    document.addEventListener("mousedown", handleClickOutside);
    return () => {
      document.removeEventListener("mousedown", handleClickOutside);
    };
  }, []);

  if (!user) return null;

  return (
    <nav className="navbar">
      <div className="navbar-container">
        <Link to="/" className="navbar-logo">
          <span className="logo-emoji">✨</span>
        </Link>

        <div className="navbar-right">
          <div className="user-greeting">Hello, {user.name}! </div>
          <div className="dropdown-container" ref={dropdownRef}>
            <button
              className="settings-button"
              onClick={() => setShowDropdown(!showDropdown)}
              aria-label="Settings menu"
            >
              <span className="settings-icon">⚙️</span>
            </button>

            {showDropdown && (
              <div className="dropdown-menu">
                <button onClick={handleSettingsClick} className="dropdown-item">
                  <span className="dropdown-icon">🔧</span>
                  Settings
                </button>
                <button onClick={handleLogout} className="dropdown-item">
                  <span className="dropdown-icon">👋</span>
                  Logout
                </button>
              </div>
            )}
          </div>
        </div>
      </div>
    </nav>
  );
};

export default Navbar;
