import { useState } from "react";
import { useNavigate, Link } from "react-router-dom";
import { useAuth } from "../context/AuthContext.jsx";
import LoadingSpinner from "./LoadingSpinner";

export default function Login() {
  const [form, setForm] = useState({ email: "", password: "" });
  const [isLoading, setIsLoading] = useState(false);
  const { login, error, setError } = useAuth();
  const navigate = useNavigate();

  const onChange = (e) => setForm({ ...form, [e.target.name]: e.target.value });
  const onSubmit = async (e) => {
    e.preventDefault();
    setError("");
    setIsLoading(true);

    try {
      const success = await login(form.email, form.password);

      if (success) {
        navigate("/");
      } else {
        setIsLoading(false);
      }
    } catch {
      setIsLoading(false);
    }
  };

  return (
    <div className="auth-card">
      <h2>Welcome Back</h2>
      <form onSubmit={onSubmit}>
        <input
          name="email"
          placeholder="Email address"
          type="email"
          onChange={onChange}
          required
          disabled={isLoading}
        />
        <input
          name="password"
          placeholder="Password"
          type="password"
          onChange={onChange}
          required
          disabled={isLoading}
        />
        {error && <div className="error-message">{error}</div>}
        <div className="forgot-password">
          <Link to="/forgot-password">Forgot Password?</Link>
        </div>
        <button type="submit" disabled={isLoading}>
          {isLoading ? (
            <>
              <LoadingSpinner size="small" /> Logging in...
            </>
          ) : (
            "Log In"
          )}
        </button>
      </form>
      <div className="form-footer">
        <p>
          No account? <Link to="/signup">Sign Up</Link>
        </p>
      </div>
    </div>
  );
}
