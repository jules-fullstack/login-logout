import { createContext, useContext } from "react";
const AuthContext = createContext({
  user: null,
  loading: true,
  error: null,
  pendingOtpVerification: null,
  isAuthenticated: false,
  login: () => {},
  logout: () => {},
});

export const useAuth = () => useContext(AuthContext);

export default AuthContext;
