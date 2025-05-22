import React from "react";

const LoadingSpinner = ({ size = "medium" }) => {
  const sizeClass =
    {
      small: "loading-spinner-small",
      medium: "loading-spinner-medium",
      large: "loading-spinner-large",
    }[size] || "loading-spinner-medium";

  return (
    <div className={`loading-spinner ${sizeClass}`}>
      <div className="spinner"></div>
    </div>
  );
};

export default LoadingSpinner;