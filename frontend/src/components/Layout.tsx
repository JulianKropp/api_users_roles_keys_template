import React, { ReactNode } from 'react';
import { useAuth } from '@/contexts/AuthContext';
import { useRouter } from 'next/navigation';
import Link from 'next/link';
import { FiUsers, FiKey, FiLock, FiLogOut, FiHome } from 'react-icons/fi';

interface LayoutProps {
  children: ReactNode;
}

const Layout: React.FC<LayoutProps> = ({ children }) => {
  const { user, isAuthenticated, logout } = useAuth();
  const router = useRouter();

  const handleLogout = async () => {
    await logout();
    router.push('/admin/login');
  };

  return (
    <div className="min-h-screen bg-gray-100">
      {isAuthenticated ? (
        <div className="flex h-screen">
          {/* Sidebar */}
          <div className="w-64 bg-gray-800 text-white">
            <div className="p-4">
              <h2 className="text-2xl font-bold">Admin Panel</h2>
              <div className="mt-2 text-sm">
                Logged in as: <span className="font-semibold">{user?.username}</span>
              </div>
            </div>
            <nav className="mt-6">
              <ul>
                <li>
                  <Link href="/admin" className="flex items-center px-4 py-3 hover:bg-gray-700">
                    <FiHome className="mr-3" />
                    Dashboard
                  </Link>
                </li>
                <li>
                  <Link href="/admin/users" className="flex items-center px-4 py-3 hover:bg-gray-700">
                    <FiUsers className="mr-3" />
                    Users
                  </Link>
                </li>
                <li>
                  <Link href="/admin/roles" className="flex items-center px-4 py-3 hover:bg-gray-700">
                    <FiLock className="mr-3" />
                    Roles
                  </Link>
                </li>
                <li>
                  <Link href="/admin/apikeys" className="flex items-center px-4 py-3 hover:bg-gray-700">
                    <FiKey className="mr-3" />
                    API Keys
                  </Link>
                </li>
                <li>
                  <button 
                    onClick={handleLogout}
                    className="flex items-center w-full text-left px-4 py-3 hover:bg-gray-700"
                  >
                    <FiLogOut className="mr-3" />
                    Logout
                  </button>
                </li>
              </ul>
            </nav>
          </div>
          
          {/* Main content */}
          <div className="flex-1 overflow-auto">
            <header className="bg-white shadow">
              <div className="px-6 py-4">
                <h1 className="text-xl font-semibold text-gray-800">
                  Admin Dashboard
                </h1>
              </div>
            </header>
            <main className="p-6">
              {children}
            </main>
          </div>
        </div>
      ) : (
        <>{children}</>
      )}
    </div>
  );
};

export default Layout;
