import { createContext, useContext } from "react";

// Create the auth context
const AuthContext = createContext();

// Create the useAuth hook
export const useAuth = () => useContext(AuthContext);

export default AuthContext;