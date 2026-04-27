import {
  Activity,
  Bell,
  BarChart3,
  LayoutDashboard,
  LogOut,
  Radio,
  Settings,
} from 'lucide-react';
import { VulnSightLogo } from './VulnSightLogo';
import { NavLink, Outlet, useNavigate } from 'react-router-dom';
import { useAuth } from '../contexts/AuthContext';
import { useAlertsWebSocket } from '../hooks/useWebSocket';
import { AlertToastContainer } from './AlertToast';
import { createContext, useContext } from 'react';
import type { Alert } from '../types';

interface LiveCtxValue {
  liveAlerts: Alert[];
  connected: boolean;
  clear: () => void;
}
const LiveCtx = createContext<LiveCtxValue>({ liveAlerts: [], connected: false, clear: () => {} });
export const useLiveAlerts = () => useContext(LiveCtx);

const NAV = [
  { to: '/', label: 'Dashboard', icon: LayoutDashboard, exact: true },
  { to: '/alerts', label: 'Alerts', icon: Bell },
  { to: '/live', label: 'Live Traffic', icon: Radio },
  { to: '/reports', label: 'Reports', icon: BarChart3 },
  { to: '/settings', label: 'Settings', icon: Settings, adminOnly: true },
];

export function Layout() {
  const { user, logout, isAdmin, isAnalyst } = useAuth();
  const navigate = useNavigate();
  const ws = useAlertsWebSocket();

  const handleLogout = () => { logout(); navigate('/login'); };

  return (
    <LiveCtx.Provider value={ws}>
      <AlertToastContainer liveAlerts={ws.liveAlerts} />
      <div className="flex h-screen overflow-hidden bg-slate-950 text-slate-100">
        {/* Sidebar */}
        <aside className="flex w-56 flex-col border-r border-slate-800 bg-slate-900/70">
          {/* Logo */}
          <div className="flex h-16 items-center gap-2.5 px-5 border-b border-slate-800">
            <div className="flex h-8 w-8 items-center justify-center rounded-lg bg-cyan-500/20 ring-1 ring-cyan-500/40 p-1.5">
              <VulnSightLogo className="h-full w-full text-cyan-400" />
            </div>
            <span className="text-base font-bold tracking-tight text-white">VulnSight</span>
          </div>

          {/* Nav */}
          <nav className="flex-1 space-y-0.5 p-3">
            {NAV.filter((n) => !n.adminOnly || isAdmin || isAnalyst).map(({ to, label, icon: Icon, exact }) => (
              <NavLink
                key={to}
                to={to}
                end={exact}
                className={({ isActive }) =>
                  `flex items-center gap-3 rounded-lg px-3 py-2.5 text-sm font-medium transition-colors ${
                    isActive
                      ? 'bg-cyan-500/15 text-cyan-400 ring-1 ring-cyan-500/30'
                      : 'text-slate-400 hover:bg-slate-800/60 hover:text-slate-200'
                  }`
                }
              >
                <Icon className="h-4 w-4 shrink-0" />
                {label}
              </NavLink>
            ))}
          </nav>

          {/* WS status + user */}
          <div className="border-t border-slate-800 p-3 space-y-2">
            <div className="flex items-center gap-2 px-3 py-1.5">
              <span className={`h-2 w-2 rounded-full ${ws.connected ? 'bg-emerald-400 animate-pulse' : 'bg-slate-600'}`} />
              <span className="text-xs text-slate-500">{ws.connected ? 'Live feed active' : 'Connecting…'}</span>
            </div>

            <div className="flex items-center gap-2.5 rounded-lg px-3 py-2">
              <div className="flex h-7 w-7 shrink-0 items-center justify-center rounded-full bg-slate-700 text-xs font-bold text-slate-200 uppercase">
                {user?.username[0]}
              </div>
              <div className="min-w-0 flex-1">
                <p className="truncate text-xs font-medium text-slate-200">{user?.username}</p>
                <p className="truncate text-xs text-slate-500">{user?.roles.join(', ')}</p>
              </div>
              <button onClick={handleLogout} title="Logout" className="text-slate-500 hover:text-red-400">
                <LogOut className="h-4 w-4" />
              </button>
            </div>
          </div>
        </aside>

        {/* Main */}
        <main className="flex flex-1 flex-col overflow-hidden">
          {/* Top bar */}
          <header className="flex h-16 items-center justify-between border-b border-slate-800 bg-slate-900/40 px-6">
            <div className="flex items-center gap-2 text-sm text-slate-400">
              <Activity className="h-4 w-4 text-cyan-500" />
              <span>Network Intrusion Detection System</span>
            </div>
            {ws.liveAlerts.length > 0 && (
              <div className="flex items-center gap-2 rounded-full bg-red-500/10 px-3 py-1 ring-1 ring-red-500/30">
                <span className="h-1.5 w-1.5 rounded-full bg-red-400 animate-pulse" />
                <span className="text-xs font-medium text-red-400">{ws.liveAlerts.length} live events</span>
              </div>
            )}
          </header>

          {/* Page content */}
          <div className="flex-1 overflow-y-auto p-6">
            <Outlet />
          </div>
        </main>
      </div>
    </LiveCtx.Provider>
  );
}
