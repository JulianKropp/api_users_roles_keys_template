'use client';

import React, { useEffect, useState } from 'react';
import { useRouter } from 'next/navigation';
import { useAuth } from '@/contexts/AuthContext';
import Layout from '@/components/Layout';
import { usersAPI, rolesAPI } from '@/utils/api';
import { useForm } from 'react-hook-form';

interface User {
  id: string;
  username: string;
  roles: string[];
  last_login?: string;
}

interface Role {
  id: string;
  rolename: string;
  endpoints: { method: string; path_filter: string }[];
}

interface UserFormData {
  username: string;
  password: string;
  roles: string[];
}

interface PasswordFormData {
  currentPassword: string;
  newPassword: string;
  confirmPassword: string;
}

export default function UsersPage() {
  const { isAuthenticated, isLoading } = useAuth();
  const router = useRouter();
  const [users, setUsers] = useState<User[]>([]);
  const [roles, setRoles] = useState<Role[]>([]);
  const [isLoadingUsers, setIsLoadingUsers] = useState(false);
  const [isLoadingRoles, setIsLoadingRoles] = useState(false);
  const [showCreateForm, setShowCreateForm] = useState(false);
  const [showPasswordForm, setShowPasswordForm] = useState(false);
  const [selectedUser, setSelectedUser] = useState<User | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [success, setSuccess] = useState<string | null>(null);

  const { register: registerUser, handleSubmit: handleSubmitUser, reset: resetUserForm, formState: { errors: userErrors } } = useForm<UserFormData>();
  const { register: registerPassword, handleSubmit: handleSubmitPassword, reset: resetPasswordForm, formState: { errors: passwordErrors }, watch } = useForm<PasswordFormData>();

  useEffect(() => {
    if (!isLoading && !isAuthenticated) {
      router.push('/admin/login');
    } else if (isAuthenticated) {
      fetchUsers();
      fetchRoles();
    }
  }, [isAuthenticated, isLoading, router]);

  const fetchUsers = async () => {
    try {
      setIsLoadingUsers(true);
      const data = await usersAPI.getAll();
      setUsers(data);
    } catch (error) {
      console.error('Failed to fetch users:', error);
      setError('Failed to load users. Please try again.');
    } finally {
      setIsLoadingUsers(false);
    }
  };

  const fetchRoles = async () => {
    try {
      setIsLoadingRoles(true);
      const data = await rolesAPI.getAll();
      setRoles(data);
    } catch (error) {
      console.error('Failed to fetch roles:', error);
    } finally {
      setIsLoadingRoles(false);
    }
  };

  const onCreateUser = async (data: UserFormData) => {
    try {
      setError(null);
      await usersAPI.create({
        username: data.username,
        password: data.password,
        roles: data.roles
      });
      setSuccess('User created successfully!');
      resetUserForm();
      setShowCreateForm(false);
      fetchUsers();
    } catch (err: any) {
      setError(err.response?.data?.detail || 'Failed to create user. Please try again.');
    }
  };

  const onChangePassword = async (data: PasswordFormData) => {
    if (!selectedUser) return;
    
    try {
      setError(null);
      await usersAPI.resetPassword(selectedUser.id, data.newPassword);
      setSuccess('Password changed successfully!');
      resetPasswordForm();
      setShowPasswordForm(false);
      setSelectedUser(null);
    } catch (err: any) {
      setError(err.response?.data?.detail || 'Failed to change password. Please try again.');
    }
  };

  const handleDeleteUser = async (userId: string) => {
    if (window.confirm('Are you sure you want to delete this user?')) {
      try {
        await usersAPI.delete(userId);
        setSuccess('User deleted successfully!');
        fetchUsers();
      } catch (err: any) {
        setError(err.response?.data?.detail || 'Failed to delete user. Please try again.');
      }
    }
  };

  const handleUpdateRoles = async (userId: string, roles: string[]) => {
    try {
      await usersAPI.setRoles(userId, roles);
      setSuccess('User roles updated successfully!');
      fetchUsers();
    } catch (err: any) {
      setError(err.response?.data?.detail || 'Failed to update user roles. Please try again.');
    }
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
          <h1 className="text-2xl font-semibold">Users Management</h1>
          <button
            onClick={() => {
              setShowCreateForm(!showCreateForm);
              setError(null);
              setSuccess(null);
              resetUserForm();
            }}
            className="bg-blue-500 hover:bg-blue-700 text-white font-bold py-2 px-4 rounded"
          >
            {showCreateForm ? 'Cancel' : 'Create User'}
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

        {showCreateForm && (
          <div className="bg-white shadow rounded-lg p-6 mb-6">
            <h2 className="text-xl font-semibold mb-4">Create New User</h2>
            <form onSubmit={handleSubmitUser(onCreateUser)}>
              <div className="grid grid-cols-1 gap-6">
                <div>
                  <label htmlFor="username" className="block text-sm font-medium text-gray-700">
                    Username
                  </label>
                  <input
                    id="username"
                    type="text"
                    {...registerUser('username', { required: 'Username is required' })}
                    className="mt-1 block w-full border border-gray-300 rounded-md shadow-sm py-2 px-3 focus:outline-none focus:ring-blue-500 focus:border-blue-500"
                  />
                  {userErrors.username && (
                    <p className="mt-1 text-sm text-red-600">{userErrors.username.message}</p>
                  )}
                </div>

                <div>
                  <label htmlFor="password" className="block text-sm font-medium text-gray-700">
                    Password
                  </label>
                  <input
                    id="password"
                    type="password"
                    {...registerUser('password', { required: 'Password is required' })}
                    className="mt-1 block w-full border border-gray-300 rounded-md shadow-sm py-2 px-3 focus:outline-none focus:ring-blue-500 focus:border-blue-500"
                  />
                  {userErrors.password && (
                    <p className="mt-1 text-sm text-red-600">{userErrors.password.message}</p>
                  )}
                </div>

                <div>
                  <label htmlFor="roles" className="block text-sm font-medium text-gray-700">
                    Roles
                  </label>
                  <select
                    id="roles"
                    multiple
                    {...registerUser('roles')}
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

                <div className="flex justify-end">
                  <button
                    type="submit"
                    className="bg-blue-500 hover:bg-blue-700 text-white font-bold py-2 px-4 rounded"
                  >
                    Create User
                  </button>
                </div>
              </div>
            </form>
          </div>
        )}

        {showPasswordForm && selectedUser && (
          <div className="bg-white shadow rounded-lg p-6 mb-6">
            <h2 className="text-xl font-semibold mb-4">Reset Password for {selectedUser.username}</h2>
            <form onSubmit={handleSubmitPassword(onChangePassword)}>
              <div className="grid grid-cols-1 gap-6">
                <div>
                  <label htmlFor="newPassword" className="block text-sm font-medium text-gray-700">
                    New Password
                  </label>
                  <input
                    id="newPassword"
                    type="password"
                    {...registerPassword('newPassword', { 
                      required: 'New password is required',
                      minLength: { value: 6, message: 'Password must be at least 6 characters' }
                    })}
                    className="mt-1 block w-full border border-gray-300 rounded-md shadow-sm py-2 px-3 focus:outline-none focus:ring-blue-500 focus:border-blue-500"
                  />
                  {passwordErrors.newPassword && (
                    <p className="mt-1 text-sm text-red-600">{passwordErrors.newPassword.message}</p>
                  )}
                </div>

                <div>
                  <label htmlFor="confirmPassword" className="block text-sm font-medium text-gray-700">
                    Confirm Password
                  </label>
                  <input
                    id="confirmPassword"
                    type="password"
                    {...registerPassword('confirmPassword', { 
                      required: 'Please confirm your password',
                      validate: (value) => value === watch('newPassword') || 'Passwords do not match'
                    })}
                    className="mt-1 block w-full border border-gray-300 rounded-md shadow-sm py-2 px-3 focus:outline-none focus:ring-blue-500 focus:border-blue-500"
                  />
                  {passwordErrors.confirmPassword && (
                    <p className="mt-1 text-sm text-red-600">{passwordErrors.confirmPassword.message}</p>
                  )}
                </div>

                <div className="flex justify-end space-x-3">
                  <button
                    type="button"
                    onClick={() => {
                      setShowPasswordForm(false);
                      setSelectedUser(null);
                      resetPasswordForm();
                    }}
                    className="bg-gray-300 hover:bg-gray-400 text-gray-800 font-bold py-2 px-4 rounded"
                  >
                    Cancel
                  </button>
                  <button
                    type="submit"
                    className="bg-blue-500 hover:bg-blue-700 text-white font-bold py-2 px-4 rounded"
                  >
                    Reset Password
                  </button>
                </div>
              </div>
            </form>
          </div>
        )}

        <div className="bg-white shadow rounded-lg overflow-hidden">
          <div className="px-4 py-5 sm:px-6">
            <h2 className="text-lg font-medium text-gray-900">Users List</h2>
            <p className="mt-1 max-w-2xl text-sm text-gray-500">
              Manage all users in the system
            </p>
          </div>
          
          {isLoadingUsers ? (
            <div className="text-center py-4 text-gray-700 dark:text-gray-300">Loading users...</div>
          ) : users.length === 0 ? (
            <div className="text-center py-4 text-gray-500 dark:text-gray-400">No users found</div>
          ) : (
            <div className="admin-table-container">
              <table className="admin-table">
                <thead>
                  <tr>
                    <th scope="col">
                      Username
                    </th>
                    <th scope="col">
                      Roles
                    </th>
                    <th scope="col">
                      Last Login
                    </th>
                    <th scope="col">
                      Actions
                    </th>
                  </tr>
                </thead>
                <tbody>
                  {users.map((user) => (
                    <tr key={user.id}>
                      <td>
                        {user.username}
                      </td>
                      <td>
                        <select
                          multiple
                          value={user.roles}
                          onChange={(e) => {
                            const selectedRoles = Array.from(e.target.selectedOptions, option => option.value);
                            handleUpdateRoles(user.id, selectedRoles);
                          }}
                          className="block w-full py-2 px-3 border border-gray-300 dark:border-gray-600 bg-white dark:bg-gray-700 rounded-md shadow-sm focus:outline-none focus:ring-blue-500 focus:border-blue-500 sm:text-sm text-gray-900 dark:text-white"
                        >
                          {roles.map(role => (
                            <option key={role.id} value={role.rolename}>
                              {role.rolename}
                            </option>
                          ))}
                        </select>
                      </td>
                      <td>
                        {user.last_login 
                          ? new Date(user.last_login).toLocaleString() 
                          : 'Never'}
                      </td>
                      <td className="space-x-2">
                        <button
                          onClick={() => {
                            setSelectedUser(user);
                            setShowPasswordForm(true);
                            setError(null);
                            setSuccess(null);
                            resetPasswordForm();
                          }}
                          className="admin-table-action-btn edit"
                        >
                          Reset Password
                        </button>
                        <button
                          onClick={() => handleDeleteUser(user.id)}
                          className="admin-table-action-btn delete"
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
