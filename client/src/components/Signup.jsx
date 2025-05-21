import { useState } from "react";
import { useNavigate, Link } from "react-router-dom";
import { useAuth } from "../context/AuthContext.jsx";
import LoadingSpinner from "./LoadingSpinner";

export default function Signup() {
  const [form, setForm] = useState({ name: "", email: "", password: "" });
  const [isLoading, setIsLoading] = useState(false);
  const { signup, error, setError } = useAuth();
  const navigate = useNavigate();

  const onChange = (e) => setForm({ ...form, [e.target.name]: e.target.value });

  const onSubmit = async (e) => {
    e.preventDefault();
    setError("");
    setIsLoading(true);

    try {
      const success = await signup(form.name, form.email, form.password);

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
      <h2>Create Account</h2>
      <form onSubmit={onSubmit}>
        <input
          name="name"
          placeholder="Full name"
          onChange={onChange}
          required
          disabled={isLoading}
        />
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
        <button type="submit" disabled={isLoading}>
          {isLoading ? (
            <>
              <LoadingSpinner size="small" /> Creating Account...
            </>
          ) : (
            "Sign Up"
          )}
        </button>
      </form>
      <div className="form-footer">
        <p>
          Already have an account? <Link to="/login">Log In</Link>
        </p>
      </div>
    </div>
  );
}
