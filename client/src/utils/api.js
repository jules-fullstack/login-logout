import axios from 'axios';

const API_URL = window._env_?.API_URL || import.meta.env.VITE_API_URL || "http://localhost:5000";

const getCsrfToken = async () => {
  try {
    const response = await axios.get(`${API_URL}/api/csrf-token`, {
      withCredentials: true
    });
    return response.data.csrfToken;
  } catch (error) {
    console.error('Failed to fetch CSRF token:', error);
    return null;
  }
};

const api = axios.create({
  baseURL: API_URL,
  withCredentials: true, 
  timeout: 30000 
});

const methodsRequiringCsrf = ['post', 'put', 'delete', 'patch'];

let csrfToken = null;

api.interceptors.request.use(
  async (config) => {
    const method = config.method.toLowerCase();
    
    // Only add CSRF token for state-changing requests
    if (methodsRequiringCsrf.includes(method) && 
        !config.url.includes('/api/csrf-token')) {
      
      // If no token stored yet, get one
      if (!csrfToken) {
        csrfToken = await getCsrfToken();
      }
      
      // Add the token to request headers
      if (csrfToken) {
        config.headers['X-CSRF-Token'] = csrfToken;
      }
    }
    
    return config;
  },
  error => Promise.reject(error)
);

api.interceptors.response.use(
  (response) => response,
  async (error) => {
    const originalRequest = error.config;
    
     // If the error is due to CSRF token being invalid (403)
    if (error.response?.status === 403 && 
        error.response?.data?.msg?.includes('CSRF token') && 
        !originalRequest._retryCSRF) {
      
      originalRequest._retryCSRF = true;
      
      // Fetch a new CSRF token
      csrfToken = await getCsrfToken();
      
      // Retry the original request
      return api(originalRequest);
    }
    
    // If the error is due to an expired token (401) and we haven't tried to refresh yet
    if (error.response?.status === 401 && !originalRequest._retry) {
      originalRequest._retry = true;
      
      try {
        await axios.post(`${API_URL}/api/auth/refresh-token`, {}, {
          withCredentials: true
        });
        
        // Retry the original request
        return api(originalRequest);
      } catch (refreshError) {
        // Only redirect for user-initiated actions, not on page load checks
        if (!originalRequest.url.includes('/api/auth/user') && 
            !originalRequest.url.includes('/api/auth/refresh-token')) {
          window.location.href = '/login';
        }
        return Promise.reject(refreshError);
      }
    }
    
    return Promise.reject(error);
  }
);

export const authAPI = {
  login: (email, password) => api.post('/api/auth/login', { email, password }),
  verifyOtp: (userId, otp) => api.post('/api/auth/verify-otp', { userId, otp }),
  resendOtp: (userId) => api.post('/api/auth/resend-otp', { userId }),
  logout: () => api.post('/api/auth/logout'),
  signup: (name, email, password) => api.post('/api/auth/signup', { name, email, password }),
  refreshToken: () => api.post('/api/auth/refresh-token'),
  getUser: () => api.get('/api/auth/user'),
  updateName: (name) => api.put('/api/auth/update-name', { name }),
  updatePassword: (currentPassword, newPassword) => api.put('/api/auth/update-password', { currentPassword, newPassword }),
  validatePassword: (password) => api.post('/api/auth/validate-password', { password }),
  deleteAccount: () => api.delete('/api/auth/delete-account'),
  verifyEmail: (token) => api.post(`/api/auth/verify-email/${token}`),
  resendVerification: (email) => api.post('/api/auth/resend-verification', { email }),
  forgotPassword: (email) => api.post('/api/auth/forgot-password', { email }),
  resetPassword: (token, password) => api.post('/api/auth/reset-password', { token, password }),
};


export default api;