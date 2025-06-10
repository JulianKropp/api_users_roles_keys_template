import axios from 'axios';

const API_URL = process.env.NEXT_PUBLIC_API_URL || 'http://localhost:8000';

const api = axios.create({
  baseURL: API_URL,
  headers: {
    'Content-Type': 'application/json',
  },
  withCredentials: true,
});

// Add request interceptor to include auth token
api.interceptors.request.use((config) => {
  const token = localStorage.getItem('authToken');
  if (token) {
    config.headers.Authorization = `Bearer ${token}`;
  }
  return config;
});

// Auth API
export const authAPI = {
  login: async (username: string, password: string) => {
    const response = await api.post('/api/v1/auth/token', {
      type: 'user',
      username,
      password,
    });
    return response.data;
  },
  logout: async () => {
    const response = await api.get('/api/v1/auth/logout');
    return response.data;
  },
  status: async () => {
    const response = await api.get('/api/v1/auth/status');
    return response.data;
  },
  sessions: async () => {
    const response = await api.get('/api/v1/auth/sessions');
    return response.data;
  },
  logoutSession: async (token: string) => {
    const response = await api.get(`/api/v1/auth/session/logout/${token}`);
    return response.data;
  },
};

// Users API
export const usersAPI = {
  getAll: async () => {
    const response = await api.get('/api/v1/users');
    return response.data;
  },
  create: async (userData: { username: string; password: string; roles?: string[] }) => {
    const response = await api.post('/api/v1/user', userData);
    return response.data;
  },
  changePassword: async (currentPassword: string, newPassword: string) => {
    const response = await api.put('/api/v1/user/password/change', {
      current_password: currentPassword,
      new_password: newPassword,
    });
    return response.data;
  },
  resetPassword: async (userId: string, newPassword: string) => {
    const response = await api.put(`/api/v1/user/${userId}/password/reset`, {
      new_password: newPassword,
    });
    return response.data;
  },
  setRoles: async (userId: string, roles: string[]) => {
    const response = await api.put(`/api/v1/user/${userId}/roles`, { roles });
    return response.data;
  },
  delete: async (userId: string) => {
    const response = await api.delete(`/api/v1/user/${userId}`);
    return response.data;
  },
};

// Roles API
export const rolesAPI = {
  getAll: async () => {
    const response = await api.get('/api/v1/roles');
    return response.data;
  },
  getById: async (roleId: string) => {
    const response = await api.get(`/api/v1/role/${roleId}`);
    return response.data;
  },
  create: async (roleData: { rolename: string; endpoints?: { method: string; path_filter: string }[] }) => {
    const response = await api.post('/api/v1/role', roleData);
    return response.data;
  },
  update: async (roleId: string, roleData: { rolename?: string; endpoints?: { method: string; path_filter: string }[] }) => {
    const response = await api.put(`/api/v1/role/${roleId}`, roleData);
    return response.data;
  },
  delete: async (roleId: string) => {
    const response = await api.delete(`/api/v1/role/${roleId}`);
    return response.data;
  },
};

// API Keys API
export const apiKeysAPI = {
  getAll: async (userId: string) => {
    const response = await api.get(`/api/v1/user/${userId}/apikeys`);
    return response.data;
  },
  getOwn: async () => {
    const response = await api.get('/api/v1/user/me/apikeys');
    return response.data;
  },
  getById: async (userId: string, apiKeyId: string) => {
    const response = await api.get(`/api/v1/user/${userId}/apikey/${apiKeyId}`);
    return response.data;
  },
  getOwnById: async (apiKeyId: string) => {
    const response = await api.get(`/api/v1/user/me/apikey/${apiKeyId}`);
    return response.data;
  },
  create: async (userId: string, apiKeyData: { roles?: string[]; expiration?: string }) => {
    const response = await api.post(`/api/v1/user/${userId}/apikey`, apiKeyData);
    return response.data;
  },
  createOwn: async (apiKeyData: { roles?: string[]; expiration?: string }) => {
    const response = await api.post('/api/v1/user/me/apikey', apiKeyData);
    return response.data;
  },
  update: async (userId: string, apiKeyId: string, apiKeyData: { roles?: string[]; expiration?: string }) => {
    const response = await api.put(`/api/v1/user/${userId}/apikey/${apiKeyId}`, apiKeyData);
    return response.data;
  },
  updateOwn: async (apiKeyId: string, apiKeyData: { roles?: string[]; expiration?: string }) => {
    const response = await api.put(`/api/v1/user/me/apikey/${apiKeyId}`, apiKeyData);
    return response.data;
  },
  delete: async (userId: string, apiKeyId: string) => {
    const response = await api.delete(`/api/v1/user/${userId}/apikey/${apiKeyId}`);
    return response.data;
  },
  deleteOwn: async (apiKeyId: string) => {
    const response = await api.delete(`/api/v1/user/me/apikey/${apiKeyId}`);
    return response.data;
  },
};

export default api;
