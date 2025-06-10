'use client';

import React, { useEffect, useState } from 'react';
import { useRouter } from 'next/navigation';
import { useAuth } from '@/contexts/AuthContext';
import Layout from '@/components/Layout';
import { apiKeysAPI, usersAPI } from '@/utils/api';
import { useForm } from 'react-hook-form';

interface APIKey {
  id: string;
  key_name: string;
  key_prefix: string;
  user_id: string;
  roles: string[];
  created_at: string;
  expires_at: string;
}

interface User {
  id: string;
  username: string;
  roles: string[];
}

interface Role {
  id: string;
  rolename: string;
}

interface APIKeyFormData {
  key_name: string;
  user_id: string;
  roles: string[];
  expires_in_days: number;
}

export default function APIKeysPage() {
  const { isAuthenticated, isLoading } = useAuth();
  const router = useRouter();
  const [apiKeys, setApiKeys] = useState<APIKey[]>([]);
  const [users, setUsers] = useState<User[]>([]);
  const [roles, setRoles] = useState<Role[]>([]);
  const [isLoadingKeys, setIsLoadingKeys] = useState(false);
  const [isLoadingUsers, setIsLoadingUsers] = useState(false);
  const [showCreateForm, setShowCreateForm] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [success, setSuccess] = useState<string | null>(null);
  const [newApiKey, setNewApiKey] = useState<string | null>(null);

  const { register, handleSubmit, reset, formState: { errors } } = useForm<APIKeyFormData>({
    defaultValues: {
      expires_in_days: 30
    }
  });

  useEffect(() => {
    if (!isLoading && !isAuthenticated) {
      router.push('/admin/login');
    } else if (isAuthenticated) {
      fetchAPIKeys();
      fetchUsers();
    }
  }, [isAuthenticated, isLoading, router]);

  const fetchAPIKeys = async () => {
    try {
      setIsLoadingKeys(true);
      const data = await apiKeysAPI.getOwn();
      setApiKeys(data);
    } catch (error) {
      console.error('Failed to fetch API keys:', error);
      setError('Failed to load API keys. Please try again.');
    } finally {
      setIsLoadingKeys(false);
    }
  };

  const fetchUsers = async () => {
    try {
      setIsLoadingUsers(true);
      const userData = await usersAPI.getAll();
      setUsers(userData);
      
      // Extract unique roles from users
      const allRoles = userData.flatMap((user: User) => user.roles);
      const uniqueRoles = Array.from(new Set(allRoles)) as string[];
      const rolesList: Role[] = uniqueRoles.map(id => ({ id, rolename: id }));
      setRoles(rolesList);
    } catch (error) {
      console.error('Failed to fetch users:', error);
    } finally {
      setIsLoadingUsers(false);
    }
  };

  const onCreateAPIKey = async (data: APIKeyFormData) => {
    try {
      setError(null);
      const response = await apiKeysAPI.createOwn({
        roles: data.roles,
        expiration: `${data.expires_in_days}d`
      });
      
      // The backend returns the API key in the response
      
      // Store the full API key to display to the user
      if (response && response.api_key) {
        setNewApiKey(response.api_key);
      }
      
      setSuccess('API key created successfully!');
      reset();
      fetchAPIKeys();
    } catch (err: any) {
      setError(err.response?.data?.detail || 'Failed to create API key. Please try again.');
    }
  };

  const handleDeleteAPIKey = async (keyId: string) => {
    if (window.confirm('Are you sure you want to delete this API key?')) {
      try {
        await apiKeysAPI.deleteOwn(keyId);
        setSuccess('API key deleted successfully!');
        fetchAPIKeys();
      } catch (err: any) {
        setError(err.response?.data?.detail || 'Failed to delete API key. Please try again.');
      }
    }
  };

  const formatDate = (dateString: string) => {
    return new Date(dateString).toLocaleString();
  };

  const getUsernameById = (userId: string) => {
    const user = users.find(u => u.id === userId);
    return user ? user.username : 'Unknown User';
  };

  if (isLoading) {
    return (
      <div className="flex items-center justify-center min-h-screen bg-gray-100">
        <div className="p-8 bg-white rounded shadow-md">
          <div className="text-center">Loading...</div>
        </div>
      </div>
    );
  }

  return (
    <Layout>
      <div className="space-y-6">
        <div className="flex justify-between items-center">
          <h1 className="text-2xl font-semibold">API Keys Management</h1>
          <button
            onClick={() => {
              setShowCreateForm(!showCreateForm);
              setError(null);
              setSuccess(null);
              setNewApiKey(null);
              reset();
            }}
            className="bg-blue-500 hover:bg-blue-700 text-white font-bold py-2 px-4 rounded"
          >
            {showCreateForm ? 'Cancel' : 'Create API Key'}
          </button>
        </div>

        {error && (
          <div className="bg-red-100 border border-red-400 text-red-700 px-4 py-3 rounded">
            {error}
          </div>
        )}

        {success && (
          <div className="bg-green-100 border border-green-400 text-green-700 px-4 py-3 rounded">
            {success}
          </div>
        )}

        {newApiKey && (
          <div className="bg-yellow-100 border border-yellow-400 text-yellow-800 px-4 py-3 rounded">
            <p className="font-bold">Important: Save this API key now. It will not be shown again!</p>
            <div className="mt-2 p-2 bg-gray-100 rounded break-all font-mono">
              {newApiKey}
            </div>
            <button 
              onClick={() => {
                navigator.clipboard.writeText(newApiKey);
                alert('API key copied to clipboard!');
              }}
              className="mt-2 bg-blue-500 hover:bg-blue-700 text-white font-bold py-1 px-3 rounded text-sm"
            >
              Copy to Clipboard
            </button>
          </div>
        )}

        {showCreateForm && (
          <div className="bg-white shadow rounded-lg p-6 mb-6">
            <h2 className="text-xl font-semibold mb-4">Create New API Key</h2>
            <form onSubmit={handleSubmit(onCreateAPIKey)}>
              <div className="grid grid-cols-1 gap-6">
                <div>
                  <label htmlFor="key_name" className="block text-sm font-medium text-gray-700">
                    Key Name
                  </label>
                  <input
                    id="key_name"
                    type="text"
                    {...register('key_name', { required: 'Key name is required' })}
                    className="mt-1 block w-full border border-gray-300 rounded-md shadow-sm py-2 px-3 focus:outline-none focus:ring-blue-500 focus:border-blue-500"
                  />
                  {errors.key_name && (
                    <p className="mt-1 text-sm text-red-600">{errors.key_name.message}</p>
                  )}
                </div>

                <div>
                  <label htmlFor="user_id" className="block text-sm font-medium text-gray-700">
                    User
                  </label>
                  <select
                    id="user_id"
                    {...register('user_id', { required: 'User is required' })}
                    className="mt-1 block w-full border border-gray-300 rounded-md shadow-sm py-2 px-3 focus:outline-none focus:ring-blue-500 focus:border-blue-500"
                  >
                    <option value="">Select a user</option>
                    {users.map((user) => (
                      <option key={user.id} value={user.id}>
                        {user.username}
                      </option>
                    ))}
                  </select>
                  {errors.user_id && (
                    <p className="mt-1 text-sm text-red-600">{errors.user_id.message}</p>
                  )}
                </div>

                <div>
                  <label htmlFor="roles" className="block text-sm font-medium text-gray-700">
                    Roles
                  </label>
                  <select
                    id="roles"
                    multiple
                    {...register('roles')}
                    className="mt-1 block w-full border border-gray-300 rounded-md shadow-sm py-2 px-3 focus:outline-none focus:ring-blue-500 focus:border-blue-500"
                  >
                    {roles.map((role) => (
                      <option key={role.id} value={role.id}>
                        {role.rolename}
                      </option>
                    ))}
                  </select>
                  <p className="mt-1 text-sm text-gray-500">Hold Ctrl/Cmd to select multiple roles</p>
                </div>

                <div>
                  <label htmlFor="expires_in_days" className="block text-sm font-medium text-gray-700">
                    Expires In (Days)
                  </label>
                  <input
                    id="expires_in_days"
                    type="number"
                    min="1"
                    max="365"
                    {...register('expires_in_days', { 
                      required: 'Expiration is required',
                      min: { value: 1, message: 'Minimum 1 day' },
                      max: { value: 365, message: 'Maximum 365 days' }
                    })}
                    className="mt-1 block w-full border border-gray-300 rounded-md shadow-sm py-2 px-3 focus:outline-none focus:ring-blue-500 focus:border-blue-500"
                  />
                  {errors.expires_in_days && (
                    <p className="mt-1 text-sm text-red-600">{errors.expires_in_days.message}</p>
                  )}
                </div>

                <div className="flex justify-end">
                  <button
                    type="submit"
                    className="bg-blue-500 hover:bg-blue-700 text-white font-bold py-2 px-4 rounded"
                  >
                    Create API Key
                  </button>
                </div>
              </div>
            </form>
          </div>
        )}

        <div className="bg-white shadow rounded-lg overflow-hidden">
          <div className="px-4 py-5 sm:px-6">
            <h2 className="text-lg font-medium text-gray-900">API Keys List</h2>
            <p className="mt-1 max-w-2xl text-sm text-gray-500">
              Manage all API keys in the system
            </p>
          </div>
          
          {isLoadingKeys ? (
            <div className="text-center py-4">Loading API keys...</div>
          ) : apiKeys.length === 0 ? (
            <div className="text-center py-4 text-gray-500">No API keys found</div>
          ) : (
            <div className="overflow-x-auto">
              <table className="min-w-full divide-y divide-gray-200">
                <thead className="bg-gray-50">
                  <tr>
                    <th scope="col" className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                      Key Name
                    </th>
                    <th scope="col" className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                      Key Prefix
                    </th>
                    <th scope="col" className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                      User
                    </th>
                    <th scope="col" className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                      Roles
                    </th>
                    <th scope="col" className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                      Created
                    </th>
                    <th scope="col" className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                      Expires
                    </th>
                    <th scope="col" className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                      Actions
                    </th>
                  </tr>
                </thead>
                <tbody className="bg-white divide-y divide-gray-200">
                  {apiKeys.map((apiKey) => (
                    <tr key={apiKey.id}>
                      <td className="px-6 py-4 whitespace-nowrap text-sm font-medium text-gray-900">
                        {apiKey.key_name}
                      </td>
                      <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-500 font-mono">
                        {apiKey.key_prefix}...
                      </td>
                      <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-500">
                        {getUsernameById(apiKey.user_id)}
                      </td>
                      <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-500">
                        {apiKey.roles.join(', ')}
                      </td>
                      <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-500">
                        {formatDate(apiKey.created_at)}
                      </td>
                      <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-500">
                        {formatDate(apiKey.expires_at)}
                      </td>
                      <td className="px-6 py-4 whitespace-nowrap text-sm font-medium">
                        <button
                          onClick={() => handleDeleteAPIKey(apiKey.id)}
                          className="text-red-600 hover:text-red-900"
                        >
                          Delete
                        </button>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </div>
      </div>
    </Layout>
  );
}
