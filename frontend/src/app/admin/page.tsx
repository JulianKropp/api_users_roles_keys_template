'use client';

import React, { useEffect, useState } from 'react';
import { useRouter } from 'next/navigation';
import { useAuth } from '@/contexts/AuthContext';
import Layout from '@/components/Layout';
import { authAPI } from '@/utils/api';

interface Session {
  token: string;
  session_type: string;
  creation_date: string;
  expiration_date: string;
  user?: {
    id: string;
    username: string;
    roles: string[];
    last_login?: string;
  };
  api_key?: {
    id: string;
    roles: string[];
    created_at: string;
    expiration?: string;
  };
}

export default function AdminDashboard() {
  const { isAuthenticated, isLoading, user } = useAuth();
  const router = useRouter();
  const [sessions, setSessions] = useState<Session[]>([]);
  const [isLoadingSessions, setIsLoadingSessions] = useState(false);

  useEffect(() => {
    if (!isLoading && !isAuthenticated) {
      router.push('/admin/login');
    } else if (isAuthenticated) {
      fetchSessions();
    }
  }, [isAuthenticated, isLoading, router]);

  const fetchSessions = async () => {
    try {
      setIsLoadingSessions(true);
      const response = await authAPI.sessions();
      setSessions(response.sessions || []);
    } catch (error) {
      console.error('Failed to fetch sessions:', error);
    } finally {
      setIsLoadingSessions(false);
    }
  };

  const handleLogoutSession = async (token: string) => {
    try {
      await authAPI.logoutSession(token);
      // Refresh sessions list
      fetchSessions();
    } catch (error) {
      console.error('Failed to logout session:', error);
    }
  };

  if (isLoading) {
    return (
      <div className="flex items-center justify-center min-h-screen bg-gray-100 dark:bg-gray-900">
        <div className="p-8 bg-white dark:bg-gray-800 rounded shadow-md border dark:border-gray-700">
          <div className="text-center text-gray-800 dark:text-gray-200">Loading...</div>
        </div>
      </div>
    );
  }

  return (
    <Layout>
      <div className="space-y-6">
        <div className="bg-white dark:bg-gray-800 shadow rounded-lg p-6 border dark:border-gray-700">
          <h2 className="text-xl font-semibold mb-4 text-gray-900 dark:text-white">Welcome, {user?.username}!</h2>
          <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
            <div className="bg-blue-50 dark:bg-blue-900/20 p-4 rounded-lg border border-blue-200 dark:border-blue-800">
              <h3 className="font-medium text-blue-700 dark:text-blue-400">User Role</h3>
              <p className="mt-2 text-gray-800 dark:text-gray-200">{user?.roles.join(', ') || 'No roles assigned'}</p>
            </div>
            <div className="bg-green-50 dark:bg-green-900/20 p-4 rounded-lg border border-green-200 dark:border-green-800">
              <h3 className="font-medium text-green-700 dark:text-green-400">Last Login</h3>
              <p className="mt-2 text-gray-800 dark:text-gray-200">
                {user?.last_login 
                  ? new Date(user.last_login).toLocaleString() 
                  : 'First login'}
              </p>
            </div>
            <div className="bg-purple-50 dark:bg-purple-900/20 p-4 rounded-lg border border-purple-200 dark:border-purple-800">
              <h3 className="font-medium text-purple-700 dark:text-purple-400">User ID</h3>
              <p className="mt-2 text-sm break-all text-gray-800 dark:text-gray-200">{user?.id || 'Unknown'}</p>
            </div>
          </div>
        </div>

        <div className="bg-white dark:bg-gray-800 shadow rounded-lg p-6 border dark:border-gray-700">
          <h2 className="text-xl font-semibold mb-4 text-gray-900 dark:text-white">Active Sessions</h2>
          
          {isLoadingSessions ? (
            <div className="text-center py-4">Loading sessions...</div>
          ) : sessions.length === 0 ? (
            <div className="text-center py-4 text-gray-500">No active sessions found</div>
          ) : (
            <div className="overflow-x-auto rounded-lg border border-gray-200 dark:border-gray-700">
              <table className="min-w-full divide-y divide-gray-200 dark:divide-gray-700">
                <thead className="bg-gray-50 dark:bg-gray-800">
                  <tr>
                    <th scope="col" className="px-6 py-3 text-left text-xs font-medium text-gray-700 dark:text-gray-300 uppercase tracking-wider">
                      Type
                    </th>
                    <th scope="col" className="px-6 py-3 text-left text-xs font-medium text-gray-700 dark:text-gray-300 uppercase tracking-wider">
                      User/API Key
                    </th>
                    <th scope="col" className="px-6 py-3 text-left text-xs font-medium text-gray-700 dark:text-gray-300 uppercase tracking-wider">
                      Created
                    </th>
                    <th scope="col" className="px-6 py-3 text-left text-xs font-medium text-gray-700 dark:text-gray-300 uppercase tracking-wider">
                      Expires
                    </th>
                    <th scope="col" className="px-6 py-3 text-left text-xs font-medium text-gray-700 dark:text-gray-300 uppercase tracking-wider">
                      Actions
                    </th>
                  </tr>
                </thead>
                <tbody className="bg-white dark:bg-gray-900 divide-y divide-gray-200 dark:divide-gray-700">
                  {sessions.map((session) => (
                    <tr key={session.token} className="hover:bg-gray-50 dark:hover:bg-gray-800">
                      <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-700 dark:text-gray-300">
                        {session.session_type}
                      </td>
                      <td className="px-6 py-4 whitespace-nowrap text-sm font-medium text-gray-900 dark:text-white">
                        {session.user?.username || session.api_key?.id || 'Unknown'}
                      </td>
                      <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-700 dark:text-gray-300">
                        {new Date(session.creation_date).toLocaleString()}
                      </td>
                      <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-700 dark:text-gray-300">
                        {new Date(session.expiration_date).toLocaleString()}
                      </td>
                      <td className="px-6 py-4 whitespace-nowrap text-sm font-medium">
                        <button
                          onClick={() => handleLogoutSession(session.token)}
                          className="text-red-600 hover:text-red-800 dark:text-red-400 dark:hover:text-red-300 font-medium"
                        >
                          Logout
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
