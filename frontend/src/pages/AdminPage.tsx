import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import {
  CheckCircle, Clock, Database, FileUp,
  RefreshCw, Settings2, Shield, Trash2, UserPlus, Users, XCircle,
} from 'lucide-react';
import { useEffect, useRef, useState } from 'react';
import {
  ApiError, deleteUser, getHealth, getThresholds,
  getPcapJob, listUsers, previewCleanup, registerUser, runCleanup,
  setThresholds, toggleUserActive, updateUserRoles, uploadPcap,
} from '../api/client';
import { useAuth } from '../contexts/AuthContext';
import { useLiveAlerts } from '../components/Layout';
import type { PcapJob, Thresholds, UserRecord } from '../types';

const AVAILABLE_ROLES = ['admin', 'analyst', 'client'];

const SEVERITIES = ['critical', 'high', 'medium', 'low', 'info'];

// ─── System Status ───────────────────────────────────────────────────────────

function SystemStatusCard() {
  const { connected } = useLiveAlerts();
  const { data: health, refetch } = useQuery({
    queryKey: ['health'],
    queryFn: getHealth,
    refetchInterval: 15_000,
  });

  const apiOk = health?.status === 'ok';

  return (
    <div className="rounded-xl border border-slate-800 bg-slate-900/60 p-6 lg:col-span-2">
      <div className="mb-5 flex items-center justify-between">
        <div className="flex items-center gap-3">
          <span className="flex h-9 w-9 items-center justify-center rounded-lg bg-slate-700/60 text-slate-300 ring-1 ring-slate-600/40">
            <Database className="h-4 w-4" />
          </span>
          <div>
            <h2 className="text-base font-semibold text-white">System Status</h2>
            <p className="text-xs text-slate-500">Live connection health and database info</p>
          </div>
        </div>
        <button
          onClick={() => refetch()}
          className="flex items-center gap-1.5 rounded-lg border border-slate-700 bg-slate-800/60 px-3 py-1.5 text-xs text-slate-400 hover:text-white transition"
        >
          <RefreshCw className="h-3.5 w-3.5" />
          Refresh
        </button>
      </div>

      <div className="grid gap-3 sm:grid-cols-2 lg:grid-cols-4">
        {/* API */}
        <div className="flex items-center gap-3 rounded-lg border border-slate-800 bg-slate-950/40 px-4 py-3">
          <span className={`h-2.5 w-2.5 shrink-0 rounded-full ${apiOk ? 'bg-emerald-400 animate-pulse' : 'bg-red-400'}`} />
          <div>
            <p className="text-xs text-slate-500">API</p>
            <p className={`text-sm font-semibold ${apiOk ? 'text-emerald-400' : 'text-red-400'}`}>
              {health?.status ?? 'unknown'}
            </p>
          </div>
        </div>

        {/* WebSocket */}
        <div className="flex items-center gap-3 rounded-lg border border-slate-800 bg-slate-950/40 px-4 py-3">
          <span className={`h-2.5 w-2.5 shrink-0 rounded-full ${connected ? 'bg-cyan-400 animate-pulse' : 'bg-slate-600'}`} />
          <div>
            <p className="text-xs text-slate-500">WebSocket</p>
            <p className={`text-sm font-semibold ${connected ? 'text-cyan-400' : 'text-slate-500'}`}>
              {connected ? 'live' : 'offline'}
            </p>
          </div>
        </div>

        {/* Database path */}
        <div className="flex items-center gap-3 rounded-lg border border-slate-800 bg-slate-950/40 px-4 py-3 sm:col-span-2">
          <Database className="h-4 w-4 shrink-0 text-slate-600" />
          <div className="min-w-0">
            <p className="text-xs text-slate-500">Database</p>
            <p className="truncate font-mono text-xs text-slate-300">{health?.database_path ?? '—'}</p>
          </div>
        </div>
      </div>

      {/* Record counts */}
      {health?.counts && (
        <div className="mt-3 grid grid-cols-4 gap-3">
          {Object.entries(health.counts).map(([k, v]) => (
            <div key={k} className="rounded-lg border border-slate-800 bg-slate-950/40 px-3 py-2.5">
              <p className="text-xs capitalize text-slate-500">{k}</p>
              <p className="mt-0.5 font-mono text-lg font-bold text-white">{v.toLocaleString()}</p>
            </div>
          ))}
        </div>
      )}
    </div>
  );
}

// ─── Data Retention ───────────────────────────────────────────────────────────

const RETENTION_PRESETS = [
  { label: 'Daily', days: 1 },
  { label: 'Weekly', days: 7 },
  { label: 'Monthly', days: 30 },
  { label: 'Quarterly', days: 90 },
  { label: 'Custom', days: null },
];

function RetentionCard() {
  const queryClient = useQueryClient();
  const [selectedPreset, setSelectedPreset] = useState<number | null>(30);
  const [customDays, setCustomDays] = useState(14);
  const [previewCount, setPreviewCount] = useState<number | null>(null);
  const [previewing, setPreviewing] = useState(false);
  const [confirmOpen, setConfirmOpen] = useState(false);
  const [success, setSuccess] = useState('');
  const [error, setError] = useState('');
  const [running, setRunning] = useState(false);

  const effectiveDays = selectedPreset !== null ? selectedPreset : customDays;

  const handlePreview = async () => {
    setPreviewing(true);
    setPreviewCount(null);
    setError('');
    try {
      const res = await previewCleanup(effectiveDays);
      setPreviewCount(res.count);
    } catch (err) {
      setError(err instanceof ApiError ? err.message : 'Preview failed');
    } finally {
      setPreviewing(false);
    }
  };

  const handleCleanup = async () => {
    setRunning(true);
    setError('');
    setSuccess('');
    try {
      const res = await runCleanup(effectiveDays);
      setSuccess(`Deleted ${res.deleted} alert${res.deleted !== 1 ? 's' : ''} older than ${effectiveDays} day${effectiveDays !== 1 ? 's' : ''}.`);
      setPreviewCount(null);
      setConfirmOpen(false);
      queryClient.invalidateQueries({ queryKey: ['alerts'] });
      queryClient.invalidateQueries({ queryKey: ['health'] });
    } catch (err) {
      setError(err instanceof ApiError ? err.message : 'Cleanup failed');
    } finally {
      setRunning(false);
    }
  };

  return (
    <div className="rounded-xl border border-slate-800 bg-slate-900/60 p-6">
      <div className="mb-5 flex items-center gap-3">
        <span className="flex h-9 w-9 items-center justify-center rounded-lg bg-orange-400/10 text-orange-400 ring-1 ring-orange-400/20">
          <Clock className="h-4 w-4" />
        </span>
        <div>
          <h2 className="text-base font-semibold text-white">Data Retention Policy</h2>
          <p className="text-xs text-slate-500">Auto-cleanup alerts older than a chosen threshold</p>
        </div>
      </div>

      {success && (
        <div className="mb-4 flex items-center gap-2 rounded-lg border border-emerald-500/30 bg-emerald-500/10 px-4 py-3 text-sm text-emerald-400">
          <CheckCircle className="h-4 w-4 shrink-0" />
          {success}
        </div>
      )}
      {error && (
        <div className="mb-4 flex items-center gap-2 rounded-lg border border-red-500/30 bg-red-500/10 px-4 py-3 text-sm text-red-400">
          <XCircle className="h-4 w-4 shrink-0" />
          {error}
        </div>
      )}

      {/* Preset buttons */}
      <div className="mb-4">
        <label className="mb-2 block text-xs font-medium text-slate-400">Retention period — keep alerts newer than:</label>
        <div className="flex flex-wrap gap-2">
          {RETENTION_PRESETS.map((p) => {
            const active = p.days !== null ? selectedPreset === p.days : selectedPreset === null;
            return (
              <button
                key={p.label}
                onClick={() => {
                  setSelectedPreset(p.days);
                  setPreviewCount(null);
                  setSuccess('');
                }}
                className={`rounded-lg border px-3 py-1.5 text-xs font-medium transition ${
                  active
                    ? 'border-orange-500/40 bg-orange-500/15 text-orange-400'
                    : 'border-slate-700 bg-slate-800/40 text-slate-400 hover:border-slate-600'
                }`}
              >
                {p.label}
              </button>
            );
          })}
        </div>
      </div>

      {/* Custom days input */}
      {selectedPreset === null && (
        <div className="mb-4">
          <label className="mb-1.5 block text-xs font-medium text-slate-400">Custom days to keep</label>
          <input
            type="number"
            min={1}
            max={3650}
            value={customDays}
            onChange={(e) => { setCustomDays(Math.max(1, Number(e.target.value))); setPreviewCount(null); }}
            className="w-28 rounded-lg border border-slate-700 bg-slate-800 px-3 py-2 text-sm text-slate-100 focus:border-cyan-500 focus:outline-none focus:ring-1 focus:ring-cyan-500"
          />
        </div>
      )}

      {/* Preview info */}
      {previewCount !== null && (
        <div className={`mb-4 rounded-lg border px-4 py-3 text-sm ${
          previewCount === 0
            ? 'border-slate-700 bg-slate-950/40 text-slate-400'
            : 'border-amber-500/30 bg-amber-500/10 text-amber-400'
        }`}>
          {previewCount === 0
            ? `No alerts found older than ${effectiveDays} day${effectiveDays !== 1 ? 's' : ''}.`
            : `${previewCount} alert${previewCount !== 1 ? 's' : ''} will be permanently deleted.`}
        </div>
      )}

      <div className="flex flex-wrap gap-2">
        <button
          onClick={handlePreview}
          disabled={previewing}
          className="flex items-center gap-2 rounded-lg border border-slate-700 bg-slate-800/60 px-4 py-2 text-sm text-slate-300 hover:text-white disabled:opacity-60 transition"
        >
          <RefreshCw className={`h-4 w-4 ${previewing ? 'animate-spin' : ''}`} />
          {previewing ? 'Checking…' : 'Preview'}
        </button>
        <button
          onClick={() => { setConfirmOpen(true); setSuccess(''); }}
          disabled={running}
          className="flex items-center gap-2 rounded-lg bg-red-600/80 px-4 py-2 text-sm font-semibold text-white hover:bg-red-600 disabled:opacity-60 transition"
        >
          <Trash2 className="h-4 w-4" />
          Run Cleanup
        </button>
      </div>

      {/* Inline confirmation */}
      {confirmOpen && (
        <div className="mt-4 rounded-lg border border-red-500/40 bg-red-500/10 px-4 py-4">
          <p className="text-sm font-semibold text-red-400">
            Delete all alerts older than {effectiveDays} day{effectiveDays !== 1 ? 's' : ''}?
          </p>
          <p className="mt-1 text-xs text-slate-400">This action cannot be undone.</p>
          <div className="mt-3 flex gap-2">
            <button
              onClick={handleCleanup}
              disabled={running}
              className="rounded-lg bg-red-600 px-4 py-1.5 text-sm font-semibold text-white hover:bg-red-500 disabled:opacity-60"
            >
              {running ? 'Deleting…' : 'Confirm Delete'}
            </button>
            <button
              onClick={() => setConfirmOpen(false)}
              className="rounded-lg border border-slate-700 px-4 py-1.5 text-sm text-slate-400 hover:text-white"
            >
              Cancel
            </button>
          </div>
        </div>
      )}
    </div>
  );
}

// ─── User Management ──────────────────────────────────────────────────────────

function UserManagementCard() {
  const queryClient = useQueryClient();
  const { user: currentUser } = useAuth();
  const [editingRoles, setEditingRoles] = useState<number | null>(null);
  const [pendingRole, setPendingRole] = useState<string>('client');
  const [deleteConfirm, setDeleteConfirm] = useState<number | null>(null);

  const { data: users = [], isLoading, error } = useQuery<UserRecord[]>({
    queryKey: ['users'],
    queryFn: listUsers,
    refetchInterval: 30_000,
  });

  const toggleActiveMutation = useMutation({
    mutationFn: ({ id, is_active }: { id: number; is_active: boolean }) =>
      toggleUserActive(id, is_active),
    onSuccess: () => queryClient.invalidateQueries({ queryKey: ['users'] }),
  });

  const deleteUserMutation = useMutation({
    mutationFn: (id: number) => deleteUser(id),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['users'] });
      setDeleteConfirm(null);
    },
  });

  const updateRolesMutation = useMutation({
    mutationFn: ({ id, roles }: { id: number; roles: string[] }) =>
      updateUserRoles(id, roles),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['users'] });
      setEditingRoles(null);
    },
  });

  const startEditRoles = (user: UserRecord) => {
    setEditingRoles(user.id);
    setPendingRole(user.roles[0] ?? 'client');   // pick the first/only role
  };

  const pickPendingRole = (role: string) => {
    setPendingRole(role);
  };

  const ROLE_COLOR: Record<string, string> = {
    admin: 'bg-red-500/15 text-red-400 ring-red-500/30',
    analyst: 'bg-amber-500/15 text-amber-400 ring-amber-500/30',
    client: 'bg-slate-700 text-slate-300 ring-slate-600/40',
  };

  return (
    <div className="rounded-xl border border-slate-800 bg-slate-900/60 p-6 lg:col-span-2">
      <div className="mb-5 flex items-center gap-3">
        <span className="flex h-9 w-9 items-center justify-center rounded-lg bg-cyan-400/10 text-cyan-400 ring-1 ring-cyan-400/20">
          <Users className="h-4 w-4" />
        </span>
        <div>
          <h2 className="text-base font-semibold text-white">User Management</h2>
          <p className="text-xs text-slate-500">View and manage all registered accounts</p>
        </div>
        <button
          onClick={() => queryClient.invalidateQueries({ queryKey: ['users'] })}
          className="ml-auto flex items-center gap-1.5 rounded-lg border border-slate-700 bg-slate-800/60 px-3 py-1.5 text-xs text-slate-400 hover:text-white transition"
        >
          <RefreshCw className="h-3.5 w-3.5" />
          Refresh
        </button>
      </div>

      {error && (
        <div className="mb-4 flex items-center gap-2 rounded-lg border border-red-500/30 bg-red-500/10 px-4 py-3 text-sm text-red-400">
          <XCircle className="h-4 w-4 shrink-0" />
          {error instanceof ApiError ? error.message : 'Failed to load users'}
        </div>
      )}

      {isLoading ? (
        <div className="py-10 text-center text-sm text-slate-500">Loading users…</div>
      ) : (
        <div className="overflow-hidden rounded-lg border border-slate-800">
          <table className="w-full border-collapse text-sm">
            <thead className="bg-slate-900/80">
              <tr>
                {['ID', 'Username', 'Roles', 'Status', 'Created', 'Actions'].map((h) => (
                  <th key={h} className="px-4 py-3 text-left text-xs font-semibold uppercase tracking-wider text-slate-400">
                    {h}
                  </th>
                ))}
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-800/60 bg-slate-950/40">
              {users.length === 0 && (
                <tr>
                  <td colSpan={6} className="py-10 text-center text-slate-500">No users found</td>
                </tr>
              )}
              {users.map((u) => (
                <>
                  <tr key={u.id} className="hover:bg-slate-800/30 transition-colors">
                    <td className="px-4 py-3 font-mono text-xs text-slate-500">{u.id}</td>
                    <td className="px-4 py-3">
                      <div className="flex items-center gap-2">
                        <div className="flex h-7 w-7 shrink-0 items-center justify-center rounded-full bg-slate-700 text-xs font-bold text-slate-200 uppercase">
                          {u.username[0]}
                        </div>
                        <span className="font-medium text-slate-200">{u.username}</span>
                        {u.username === currentUser?.username && (
                          <span className="rounded bg-cyan-500/15 px-1.5 py-0.5 text-[10px] text-cyan-400">you</span>
                        )}
                      </div>
                    </td>
                    <td className="px-4 py-3">
                      {editingRoles === u.id ? (
                        <div className="flex flex-wrap gap-1">
                          {AVAILABLE_ROLES.map((role) => (
                            <button
                              key={role}
                              onClick={() => pickPendingRole(role)}
                              className={`rounded px-2 py-0.5 text-[11px] font-medium ring-1 transition ${
                                pendingRole === role
                                  ? ROLE_COLOR[role] ?? 'bg-slate-700 text-slate-300 ring-slate-600/40'
                                  : 'bg-slate-800/40 text-slate-500 ring-slate-700 opacity-40 hover:opacity-70'
                              }`}
                            >
                              {role}
                            </button>
                          ))}
                        </div>
                      ) : (
                        <div className="flex flex-wrap gap-1">
                          {u.roles.map((r) => (
                            <span
                              key={r}
                              className={`rounded px-2 py-0.5 text-[11px] font-medium ring-1 ${ROLE_COLOR[r] ?? 'bg-slate-700 text-slate-300 ring-slate-600/40'}`}
                            >
                              {r}
                            </span>
                          ))}
                        </div>
                      )}
                    </td>
                    <td className="px-4 py-3">
                      <span className={`inline-flex items-center gap-1.5 rounded-full px-2 py-0.5 text-xs font-medium ring-1 ${
                        u.is_active
                          ? 'bg-emerald-500/15 text-emerald-400 ring-emerald-500/30'
                          : 'bg-slate-800 text-slate-500 ring-slate-700'
                      }`}>
                        <span className={`h-1.5 w-1.5 rounded-full ${u.is_active ? 'bg-emerald-400' : 'bg-slate-600'}`} />
                        {u.is_active ? 'Active' : 'Inactive'}
                      </span>
                    </td>
                    <td className="px-4 py-3 font-mono text-xs text-slate-500">
                      {u.created_at ? new Date(u.created_at).toLocaleDateString() : '—'}
                    </td>
                    <td className="px-4 py-3">
                      {editingRoles === u.id ? (
                        <div className="flex items-center gap-2">
                          <button
                            onClick={() => updateRolesMutation.mutate({ id: u.id, roles: [pendingRole] })}
                            disabled={updateRolesMutation.isPending}
                            className="rounded bg-cyan-600 px-2.5 py-1 text-xs font-semibold text-white hover:bg-cyan-500 disabled:opacity-50"
                          >
                            {updateRolesMutation.isPending ? '…' : 'Save'}
                          </button>
                          <button
                            onClick={() => setEditingRoles(null)}
                            className="rounded border border-slate-700 px-2.5 py-1 text-xs text-slate-400 hover:text-white"
                          >
                            Cancel
                          </button>
                        </div>
                      ) : (
                        <div className="flex items-center gap-1.5">
                          {/* Toggle active */}
                          <button
                            onClick={() => toggleActiveMutation.mutate({ id: u.id, is_active: !u.is_active })}
                            disabled={u.username === currentUser?.username || toggleActiveMutation.isPending}
                            title={u.is_active ? 'Deactivate' : 'Activate'}
                            className={`rounded border px-2 py-1 text-xs transition disabled:opacity-30 ${
                              u.is_active
                                ? 'border-amber-500/30 text-amber-400 hover:bg-amber-500/10'
                                : 'border-emerald-500/30 text-emerald-400 hover:bg-emerald-500/10'
                            }`}
                          >
                            {u.is_active ? 'Disable' : 'Enable'}
                          </button>
                          {/* Edit roles */}
                          <button
                            onClick={() => startEditRoles(u)}
                            title="Edit roles"
                            className="rounded border border-slate-700 px-2 py-1 text-xs text-slate-400 hover:border-cyan-500/40 hover:text-cyan-400 transition"
                          >
                            <Shield className="h-3 w-3" />
                          </button>
                          {/* Delete */}
                          <button
                            onClick={() => setDeleteConfirm(u.id)}
                            disabled={u.username === currentUser?.username}
                            title="Delete user"
                            className="rounded border border-slate-700 px-2 py-1 text-xs text-slate-400 hover:border-red-500/40 hover:text-red-400 transition disabled:opacity-30"
                          >
                            <Trash2 className="h-3 w-3" />
                          </button>
                        </div>
                      )}
                    </td>
                  </tr>
                  {/* Delete confirmation row */}
                  {deleteConfirm === u.id && (
                    <tr key={`${u.id}-confirm`} className="bg-red-950/30">
                      <td colSpan={6} className="px-4 py-3">
                        <div className="flex items-center gap-3 text-sm">
                          <XCircle className="h-4 w-4 shrink-0 text-red-400" />
                          <span className="text-red-400">
                            Delete <strong>{u.username}</strong>? This cannot be undone.
                          </span>
                          <button
                            onClick={() => deleteUserMutation.mutate(u.id)}
                            disabled={deleteUserMutation.isPending}
                            className="rounded bg-red-600 px-3 py-1 text-xs font-semibold text-white hover:bg-red-500 disabled:opacity-60"
                          >
                            {deleteUserMutation.isPending ? 'Deleting…' : 'Confirm'}
                          </button>
                          <button
                            onClick={() => setDeleteConfirm(null)}
                            className="rounded border border-slate-700 px-3 py-1 text-xs text-slate-400 hover:text-white"
                          >
                            Cancel
                          </button>
                        </div>
                      </td>
                    </tr>
                  )}
                </>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
}


// ─── Register User ────────────────────────────────────────────────────────────

function RegisterUserCard() {
  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');
  const [selectedRole, setSelectedRole] = useState<string>('client');
  const [success, setSuccess] = useState('');
  const queryClient = useQueryClient();

  const { mutate, isPending, error, reset } = useMutation({
    mutationFn: () => registerUser(username, password, [selectedRole]),
    onSuccess: (user) => {
      setSuccess(`User "${user.username}" created with role: ${user.roles.join(', ')}`);
      setUsername('');
      setPassword('');
      setSelectedRole('client');
      queryClient.invalidateQueries({ queryKey: ['users'] });
    },
  });

  const pickRole = (role: string) => {
    setSelectedRole(role);
    reset();
    setSuccess('');
  };

  return (
    <div className="rounded-xl border border-slate-800 bg-slate-900/60 p-6">
      <div className="mb-5 flex items-center gap-3">
        <span className="flex h-9 w-9 items-center justify-center rounded-lg bg-purple-400/10 text-purple-400 ring-1 ring-purple-400/20">
          <UserPlus className="h-4 w-4" />
        </span>
        <div>
          <h2 className="text-base font-semibold text-white">Register User</h2>
          <p className="text-xs text-slate-500">Create a new account with a single role</p>
        </div>
      </div>

      {success && (
        <div className="mb-4 flex items-center gap-2 rounded-lg border border-emerald-500/30 bg-emerald-500/10 px-4 py-3 text-sm text-emerald-400">
          <CheckCircle className="h-4 w-4 shrink-0" />
          {success}
        </div>
      )}
      {error && (
        <div className="mb-4 flex items-center gap-2 rounded-lg border border-red-500/30 bg-red-500/10 px-4 py-3 text-sm text-red-400">
          <XCircle className="h-4 w-4 shrink-0" />
          {error instanceof ApiError ? error.message : 'Registration failed'}
        </div>
      )}

      <form
        onSubmit={(e) => { e.preventDefault(); reset(); setSuccess(''); mutate(); }}
        className="space-y-4"
      >
        <div className="grid gap-4 sm:grid-cols-2">
          <div>
            <label className="mb-1.5 block text-xs font-medium text-slate-400">Username</label>
            <input
              value={username}
              onChange={(e) => setUsername(e.target.value)}
              required
              minLength={3}
              className="w-full rounded-lg border border-slate-700 bg-slate-800/60 px-3 py-2.5 text-sm text-slate-100 focus:border-cyan-500 focus:outline-none focus:ring-1 focus:ring-cyan-500"
              placeholder="johndoe"
            />
          </div>
          <div>
            <label className="mb-1.5 block text-xs font-medium text-slate-400">Password</label>
            <input
              type="password"
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              required
              minLength={8}
              className="w-full rounded-lg border border-slate-700 bg-slate-800/60 px-3 py-2.5 text-sm text-slate-100 focus:border-cyan-500 focus:outline-none focus:ring-1 focus:ring-cyan-500"
              placeholder="min. 8 characters"
            />
          </div>
        </div>

        <div>
          <label className="mb-2 block text-xs font-medium text-slate-400">Role</label>
          <div className="flex flex-wrap gap-2">
            {AVAILABLE_ROLES.map((role) => (
              <button
                key={role}
                type="button"
                onClick={() => pickRole(role)}
                className={`rounded-lg border px-3 py-1.5 text-xs font-medium transition ${
                  selectedRole === role
                    ? 'border-cyan-500/40 bg-cyan-500/15 text-cyan-400'
                    : 'border-slate-700 bg-slate-800/40 text-slate-400 hover:border-slate-600'
                }`}
              >
                {role}
              </button>
            ))}
          </div>
        </div>

        <button
          type="submit"
          disabled={isPending}
          className="flex items-center gap-2 rounded-lg bg-cyan-500 px-4 py-2 text-sm font-semibold text-slate-950 hover:bg-cyan-400 disabled:opacity-60"
        >
          {isPending ? 'Creating…' : 'Create User'}
        </button>
      </form>
    </div>
  );
}

// ─── PCAP Upload ─────────────────────────────────────────────────────────────

function PcapUploadCard() {
  const queryClient = useQueryClient();
  const fileRef = useRef<HTMLInputElement>(null);
  const [job, setJob] = useState<PcapJob | null>(null);
  const [uploading, setUploading] = useState(false);
  const [error, setError] = useState('');

  const pollRef = useRef<ReturnType<typeof setInterval> | null>(null);
  useEffect(() => {
    if (job && (job.status === 'queued' || job.status === 'processing')) {
      pollRef.current = setInterval(async () => {
        try {
          const updated = await getPcapJob(job.job_id);
          setJob(updated);
          if (updated.status === 'done' || updated.status === 'error') {
            clearInterval(pollRef.current!);
            queryClient.invalidateQueries({ queryKey: ['alerts'] });
          }
        } catch {}
      }, 2000);
    }
    return () => { if (pollRef.current) clearInterval(pollRef.current); };
  }, [job?.job_id, job?.status, queryClient]);

  const handleUpload = async (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0];
    if (!file) return;
    setUploading(true);
    setError('');
    setJob(null);
    try {
      const result = await uploadPcap(file);
      setJob(result);
    } catch (err) {
      setError(err instanceof ApiError ? err.message : 'Upload failed');
    } finally {
      setUploading(false);
      if (fileRef.current) fileRef.current.value = '';
    }
  };

  const statusColor = job?.status === 'done' ? 'text-emerald-400'
    : job?.status === 'error' ? 'text-red-400'
    : 'text-cyan-400';

  return (
    <div className="rounded-xl border border-slate-800 bg-slate-900/60 p-6">
      <div className="mb-5 flex items-center gap-3">
        <span className="flex h-9 w-9 items-center justify-center rounded-lg bg-violet-400/10 text-violet-400 ring-1 ring-violet-400/20">
          <FileUp className="h-4 w-4" />
        </span>
        <div>
          <h2 className="text-base font-semibold text-white">PCAP Analysis</h2>
          <p className="text-xs text-slate-500">Upload a .pcap file for offline threat detection</p>
        </div>
      </div>

      {error && (
        <div className="mb-4 flex items-center gap-2 rounded-lg border border-red-500/30 bg-red-500/10 px-4 py-3 text-sm text-red-400">
          <XCircle className="h-4 w-4 shrink-0" />
          {error}
        </div>
      )}

      {job && (
        <div className={`mb-4 rounded-lg border border-slate-700 bg-slate-950/60 px-4 py-3 text-sm ${statusColor}`}>
          <p className="font-semibold capitalize">{job.status === 'processing' ? '⏳ Processing…' : job.status === 'done' ? '✅ Complete' : job.status === 'error' ? '❌ Error' : '📋 Queued'}</p>
          <p className="mt-1 text-xs text-slate-400">{job.filename}</p>
          {(job.status === 'done') && (
            <p className="mt-1 text-xs">
              {job.flows_processed} flows → <strong>{job.alerts_saved} alerts saved</strong>
            </p>
          )}
          {job.status === 'error' && job.error && (
            <p className="mt-1 text-xs text-red-400">{job.error}</p>
          )}
        </div>
      )}

      <label className={`flex cursor-pointer items-center gap-2 rounded-lg border-2 border-dashed border-slate-700 px-4 py-6 text-center transition hover:border-violet-500/60 hover:bg-violet-500/5 ${uploading ? 'opacity-60 pointer-events-none' : ''}`}>
        <input
          ref={fileRef}
          type="file"
          accept=".pcap,.pcapng,.cap"
          onChange={handleUpload}
          className="sr-only"
          disabled={uploading}
        />
        <FileUp className="h-5 w-5 text-slate-500" />
        <span className="text-sm text-slate-400">
          {uploading ? 'Uploading…' : 'Click to select a .pcap / .pcapng file'}
        </span>
      </label>
    </div>
  );
}

// ─── Thresholds ───────────────────────────────────────────────────────────────

function ThresholdsCard() {
  const queryClient = useQueryClient();
  const { data: thresholds } = useQuery<Thresholds>({
    queryKey: ['thresholds'],
    queryFn: getThresholds,
    retry: false,
  });

  const [local, setLocal] = useState<Partial<Thresholds>>({});
  const [saving, setSaving] = useState(false);
  const [saved, setSaved] = useState(false);

  useEffect(() => {
    if (thresholds) setLocal(thresholds);
  }, [thresholds]);

  const effective = { ...thresholds, ...local } as Thresholds;

  const handleSave = async () => {
    setSaving(true);
    setSaved(false);
    try {
      await setThresholds(local);
      queryClient.invalidateQueries({ queryKey: ['thresholds'] });
      setSaved(true);
      setTimeout(() => setSaved(false), 3000);
    } finally {
      setSaving(false);
    }
  };

  const notifSevs: string[] = effective.alert_notification_severities ?? ['critical', 'high'];

  const toggleSev = (sev: string) => {
    const next = notifSevs.includes(sev)
      ? notifSevs.filter((s) => s !== sev)
      : [...notifSevs, sev];
    setLocal((p) => ({ ...p, alert_notification_severities: next }));
  };

  return (
    <div className="rounded-xl border border-slate-800 bg-slate-900/60 p-6">
      <div className="mb-5 flex items-center gap-3">
        <span className="flex h-9 w-9 items-center justify-center rounded-lg bg-emerald-400/10 text-emerald-400 ring-1 ring-emerald-400/20">
          <Settings2 className="h-4 w-4" />
        </span>
        <div>
          <h2 className="text-base font-semibold text-white">Alert Preferences</h2>
          <p className="text-xs text-slate-500">Deduplication window and toast notification severities</p>
        </div>
      </div>

      <div className="space-y-5">
        <div>
          <label className="mb-1.5 block text-xs font-medium text-slate-400">
            Dedup window — <span className="text-cyan-400">{effective.dedup_window_seconds ?? 60} s</span>
          </label>
          <input
            type="range" min={10} max={600} step={10}
            value={effective.dedup_window_seconds ?? 60}
            onChange={(e) => setLocal((p) => ({ ...p, dedup_window_seconds: parseInt(e.target.value) }))}
            className="w-full accent-cyan-500"
          />
          <div className="mt-0.5 flex justify-between text-xs text-slate-600">
            <span>10 s</span><span>600 s</span>
          </div>
        </div>

        <div>
          <label className="mb-2 block text-xs font-medium text-slate-400">Toast notification severities</label>
          <div className="flex flex-wrap gap-2">
            {SEVERITIES.map((sev) => (
              <button
                key={sev}
                type="button"
                onClick={() => toggleSev(sev)}
                className={`rounded-lg border px-3 py-1 text-xs font-medium transition ${
                  notifSevs.includes(sev)
                    ? 'border-cyan-500/40 bg-cyan-500/15 text-cyan-400'
                    : 'border-slate-700 bg-slate-800/40 text-slate-500 hover:border-slate-600'
                }`}
              >
                {sev}
              </button>
            ))}
          </div>
        </div>

        <button
          onClick={handleSave}
          disabled={saving}
          className="flex items-center gap-2 rounded-lg bg-emerald-600 px-4 py-2 text-sm font-semibold text-white hover:bg-emerald-500 disabled:opacity-60"
        >
          {saved ? <><CheckCircle className="h-4 w-4" /> Saved!</> : saving ? 'Saving…' : 'Save Thresholds'}
        </button>
      </div>
    </div>
  );
}

// ─── Page ─────────────────────────────────────────────────────────────────────

export function AdminPage() {
  const { isAdmin } = useAuth();

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-xl font-bold text-white">Settings</h1>
        <p className="mt-0.5 text-sm text-slate-500">System status, configuration, and user administration</p>
      </div>

      <div className="grid gap-6 lg:grid-cols-2">
        <SystemStatusCard />
        <ThresholdsCard />
        <RetentionCard />
        <PcapUploadCard />
        {isAdmin && <RegisterUserCard />}
        {isAdmin && <UserManagementCard />}
      </div>
    </div>
  );
}
