import { Navigate, Outlet } from 'react-router-dom';
import { useAuth } from '../contexts/AuthContext';

interface Props {
  roles?: string[];
}

export function ProtectedRoute({ roles }: Props) {
  const { user, isLoading } = useAuth();

  if (isLoading) {
    return (
      <div className="flex h-screen items-center justify-center bg-slate-950">
        <div className="h-8 w-8 animate-spin rounded-full border-2 border-slate-700 border-t-cyan-400" />
      </div>
    );
  }

  if (!user) return <Navigate to="/login" replace />;

  if (roles && !user.roles.some((r) => roles.includes(r))) {
    return <Navigate to="/" replace />;
  }

  return <Outlet />;
}
