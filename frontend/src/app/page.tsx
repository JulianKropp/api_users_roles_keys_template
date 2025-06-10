'use client';

import { useEffect } from 'react';
import { useRouter } from 'next/navigation';

export default function Home() {
  const router = useRouter();

  useEffect(() => {
    // Automatische Weiterleitung zur Admin-Login-Seite
    router.push('/admin/login');
  }, [router]);

  return (
    <div className="flex items-center justify-center min-h-screen bg-gray-100">
      <div className="p-8 bg-white rounded shadow-md text-center">
        <h1 className="text-2xl font-semibold mb-4">API Management Portal</h1>
        <p className="mb-4">Weiterleitung zur Anmeldeseite...</p>
        <div className="animate-spin rounded-full h-8 w-8 border-b-2 border-blue-500 mx-auto"></div>
        <div className="mt-4">
          <a 
            href="/admin/login" 
            className="text-blue-500 hover:text-blue-700 underline"
          >
            Klicken Sie hier, wenn Sie nicht automatisch weitergeleitet werden
          </a>
        </div>
      </div>
    </div>
  );
}
 