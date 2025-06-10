'use client';

import React, { useEffect, useState } from 'react';
import { useRouter } from 'next/navigation';
import { useAuth } from '@/contexts/AuthContext';
import Layout from '@/components/Layout';
import { rolesAPI } from '@/utils/api';
import { useForm } from 'react-hook-form';

interface Endpoint {
  method: string;
  path_filter: string;
}

interface Role {
  id: string;
  rolename: string;
  endpoints: Endpoint[];
}

interface RoleFormData {
  rolename: string;
  endpoints: Endpoint[];
}

export default function RolesPage() {
  const { isAuthenticated, isLoading } = useAuth();
  const router = useRouter();
  const [roles, setRoles] = useState<Role[]>([]);
  const [isLoadingRoles, setIsLoadingRoles] = useState(false);
  const [showCreateForm, setShowCreateForm] = useState(false);
  const [showEditForm, setShowEditForm] = useState(false);
  const [selectedRole, setSelectedRole] = useState<Role | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [success, setSuccess] = useState<string | null>(null);
  const [endpoints, setEndpoints] = useState<Endpoint[]>([{ method: 'GET', path_filter: '/' }]);

  const { register, handleSubmit, reset, setValue, formState: { errors } } = useForm<RoleFormData>();

  useEffect(() => {
    if (!isLoading && !isAuthenticated) {
      router.push('/admin/login');
    } else if (isAuthenticated) {
      fetchRoles();
    }
  }, [isAuthenticated, isLoading, router]);

  useEffect(() => {
    if (selectedRole && showEditForm) {
      setValue('rolename', selectedRole.rolename);
      setEndpoints(selectedRole.endpoints);
    }
  }, [selectedRole, showEditForm, setValue]);

  const fetchRoles = async () => {
    try {
      setIsLoadingRoles(true);
      const data = await rolesAPI.getAll();
      setRoles(data);
    } catch (error) {
      console.error('Failed to fetch roles:', error);
      setError('Failed to load roles. Please try again.');
    } finally {
      setIsLoadingRoles(false);
    }
  };

  const onCreateRole = async (data: RoleFormData) => {
    try {
      setError(null);
      await rolesAPI.create({
        rolename: data.rolename,
        endpoints: endpoints
      });
      setSuccess('Role created successfully!');
      reset();
      setEndpoints([{ method: 'GET', path_filter: '/' }]);
      setShowCreateForm(false);
      fetchRoles();
    } catch (err: any) {
      setError(err.response?.data?.detail || 'Failed to create role. Please try again.');
    }
  };

  const onUpdateRole = async (data: RoleFormData) => {
    if (!selectedRole) return;
    
    try {
      setError(null);
      await rolesAPI.update(selectedRole.id, {
        rolename: data.rolename,
        endpoints: endpoints
      });
      setSuccess('Role updated successfully!');
      reset();
      setEndpoints([{ method: 'GET', path_filter: '/' }]);
      setShowEditForm(false);
      setSelectedRole(null);
      fetchRoles();
    } catch (err: any) {
      setError(err.response?.data?.detail || 'Failed to update role. Please try again.');
    }
  };

  const handleDeleteRole = async (roleId: string) => {
    if (window.confirm('Are you sure you want to delete this role?')) {
      try {
        await rolesAPI.delete(roleId);
        setSuccess('Role deleted successfully!');
        fetchRoles();
      } catch (err: any) {
        setError(err.response?.data?.detail || 'Failed to delete role. Please try again.');
      }
    }
  };

  const addEndpoint = () => {
    setEndpoints([...endpoints, { method: 'GET', path_filter: '/' }]);
  };

  const removeEndpoint = (index: number) => {
    const newEndpoints = [...endpoints];
    newEndpoints.splice(index, 1);
    setEndpoints(newEndpoints);
  };

  const updateEndpoint = (index: number, field: 'method' | 'path_filter', value: string) => {
    const newEndpoints = [...endpoints];
    newEndpoints[index][field] = value;
    setEndpoints(newEndpoints);
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
          <h1 className="text-2xl font-semibold">Roles Management</h1>
          <button
            onClick={() => {
              setShowCreateForm(!showCreateForm);
              setShowEditForm(false);
              setSelectedRole(null);
              setError(null);
              setSuccess(null);
              reset();
              setEndpoints([{ method: 'GET', path_filter: '/' }]);
            }}
            className="bg-blue-500 hover:bg-blue-700 text-white font-bold py-2 px-4 rounded"
          >
            {showCreateForm ? 'Cancel' : 'Create Role'}
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
            <h2 className="text-xl font-semibold mb-4">Create New Role</h2>
            <form onSubmit={handleSubmit(onCreateRole)}>
              <div className="grid grid-cols-1 gap-6">
                <div>
                  <label htmlFor="rolename" className="block text-sm font-medium text-gray-700">
                    Role Name
                  </label>
                  <input
                    id="rolename"
                    type="text"
                    {...register('rolename', { required: 'Role name is required' })}
                    className="mt-1 block w-full border border-gray-300 rounded-md shadow-sm py-2 px-3 focus:outline-none focus:ring-blue-500 focus:border-blue-500"
                  />
                  {errors.rolename && (
                    <p className="mt-1 text-sm text-red-600">{errors.rolename.message}</p>
                  )}
                </div>

                <div>
                  <label className="block text-sm font-medium text-gray-700 mb-2">
                    Endpoints
                  </label>
                  {endpoints.map((endpoint, index) => (
                    <div key={index} className="flex items-center space-x-2 mb-2">
                      <select
                        value={endpoint.method}
                        onChange={(e) => updateEndpoint(index, 'method', e.target.value)}
                        className="border border-gray-300 rounded-md shadow-sm py-2 px-3 focus:outline-none focus:ring-blue-500 focus:border-blue-500"
                      >
                        <option value="GET">GET</option>
                        <option value="POST">POST</option>
                        <option value="PUT">PUT</option>
                        <option value="DELETE">DELETE</option>
                        <option value="PATCH">PATCH</option>
                        <option value="ANY">ANY</option>
                      </select>
                      <input
                        type="text"
                        value={endpoint.path_filter}
                        onChange={(e) => updateEndpoint(index, 'path_filter', e.target.value)}
                        placeholder="Path filter (e.g. /users/*)"
                        className="flex-1 border border-gray-300 rounded-md shadow-sm py-2 px-3 focus:outline-none focus:ring-blue-500 focus:border-blue-500"
                      />
                      <button
                        type="button"
                        onClick={() => removeEndpoint(index)}
                        className="bg-red-500 hover:bg-red-700 text-white font-bold py-1 px-3 rounded"
                      >
                        Remove
                      </button>
                    </div>
                  ))}
                  <button
                    type="button"
                    onClick={addEndpoint}
                    className="mt-2 bg-gray-200 hover:bg-gray-300 text-gray-800 font-bold py-2 px-4 rounded"
                  >
                    Add Endpoint
                  </button>
                </div>

                <div className="flex justify-end">
                  <button
                    type="submit"
                    className="bg-blue-500 hover:bg-blue-700 text-white font-bold py-2 px-4 rounded"
                  >
                    Create Role
                  </button>
                </div>
              </div>
            </form>
          </div>
        )}

        {showEditForm && selectedRole && (
          <div className="bg-white shadow rounded-lg p-6 mb-6">
            <h2 className="text-xl font-semibold mb-4">Edit Role: {selectedRole.rolename}</h2>
            <form onSubmit={handleSubmit(onUpdateRole)}>
              <div className="grid grid-cols-1 gap-6">
                <div>
                  <label htmlFor="rolename" className="block text-sm font-medium text-gray-700">
                    Role Name
                  </label>
                  <input
                    id="rolename"
                    type="text"
                    {...register('rolename', { required: 'Role name is required' })}
                    className="mt-1 block w-full border border-gray-300 rounded-md shadow-sm py-2 px-3 focus:outline-none focus:ring-blue-500 focus:border-blue-500"
                  />
                  {errors.rolename && (
                    <p className="mt-1 text-sm text-red-600">{errors.rolename.message}</p>
                  )}
                </div>

                <div>
                  <label className="block text-sm font-medium text-gray-700 mb-2">
                    Endpoints
                  </label>
                  {endpoints.map((endpoint, index) => (
                    <div key={index} className="flex items-center space-x-2 mb-2">
                      <select
                        value={endpoint.method}
                        onChange={(e) => updateEndpoint(index, 'method', e.target.value)}
                        className="border border-gray-300 rounded-md shadow-sm py-2 px-3 focus:outline-none focus:ring-blue-500 focus:border-blue-500"
                      >
                        <option value="GET">GET</option>
                        <option value="POST">POST</option>
                        <option value="PUT">PUT</option>
                        <option value="DELETE">DELETE</option>
                        <option value="PATCH">PATCH</option>
                        <option value="ANY">ANY</option>
                      </select>
                      <input
                        type="text"
                        value={endpoint.path_filter}
                        onChange={(e) => updateEndpoint(index, 'path_filter', e.target.value)}
                        placeholder="Path filter (e.g. /users/*)"
                        className="flex-1 border border-gray-300 rounded-md shadow-sm py-2 px-3 focus:outline-none focus:ring-blue-500 focus:border-blue-500"
                      />
                      <button
                        type="button"
                        onClick={() => removeEndpoint(index)}
                        className="bg-red-500 hover:bg-red-700 text-white font-bold py-1 px-3 rounded"
                      >
                        Remove
                      </button>
                    </div>
                  ))}
                  <button
                    type="button"
                    onClick={addEndpoint}
                    className="mt-2 bg-gray-200 hover:bg-gray-300 text-gray-800 font-bold py-2 px-4 rounded"
                  >
                    Add Endpoint
                  </button>
                </div>

                <div className="flex justify-end space-x-3">
                  <button
                    type="button"
                    onClick={() => {
                      setShowEditForm(false);
                      setSelectedRole(null);
                      reset();
                      setEndpoints([{ method: 'GET', path_filter: '/' }]);
                    }}
                    className="bg-gray-300 hover:bg-gray-400 text-gray-800 font-bold py-2 px-4 rounded"
                  >
                    Cancel
                  </button>
                  <button
                    type="submit"
                    className="bg-blue-500 hover:bg-blue-700 text-white font-bold py-2 px-4 rounded"
                  >
                    Update Role
                  </button>
                </div>
              </div>
            </form>
          </div>
        )}

        <div className="bg-white shadow rounded-lg overflow-hidden">
          <div className="px-4 py-5 sm:px-6">
            <h2 className="text-lg font-medium text-gray-900">Roles List</h2>
            <p className="mt-1 max-w-2xl text-sm text-gray-500">
              Manage all roles in the system
            </p>
          </div>
          
          {isLoadingRoles ? (
            <div className="text-center py-4">Loading roles...</div>
          ) : roles.length === 0 ? (
            <div className="text-center py-4 text-gray-500">No roles found</div>
          ) : (
            <div className="overflow-x-auto">
              <table className="min-w-full divide-y divide-gray-200">
                <thead className="bg-gray-50">
                  <tr>
                    <th scope="col" className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                      Role Name
                    </th>
                    <th scope="col" className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                      Endpoints
                    </th>
                    <th scope="col" className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                      Actions
                    </th>
                  </tr>
                </thead>
                <tbody className="bg-white divide-y divide-gray-200">
                  {roles.map((role) => (
                    <tr key={role.id}>
                      <td className="px-6 py-4 whitespace-nowrap text-sm font-medium text-gray-900">
                        {role.rolename}
                      </td>
                      <td className="px-6 py-4 text-sm text-gray-500">
                        <div className="max-h-40 overflow-y-auto">
                          {role.endpoints.map((endpoint, index) => (
                            <div key={index} className="mb-1">
                              <span className="font-medium">{endpoint.method}</span>: {endpoint.path_filter}
                            </div>
                          ))}
                        </div>
                      </td>
                      <td className="px-6 py-4 whitespace-nowrap text-sm font-medium">
                        <div className="flex space-x-3">
                          <button
                            onClick={() => {
                              setSelectedRole(role);
                              setShowEditForm(true);
                              setShowCreateForm(false);
                              setError(null);
                              setSuccess(null);
                            }}
                            className="text-blue-600 hover:text-blue-900"
                          >
                            Edit
                          </button>
                          <button
                            onClick={() => handleDeleteRole(role.id)}
                            className="text-red-600 hover:text-red-900"
                          >
                            Delete
                          </button>
                        </div>
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
