import {
  Brain,
  Cpu,
  Database,
  FlaskConical,
  Layers,
  Settings as SettingsIcon,
  TrendingUp,
  ShieldCheck,
} from 'lucide-react';

// ---------------------------------------------------------------------------
// Data
// ---------------------------------------------------------------------------

const FEATURES = [
  { id: 1,  name: 'Flow Duration',                    description: 'Total duration of the flow in microseconds',                   category: 'Flow'        },
  { id: 2,  name: 'Total Forward Packets',            description: 'Number of packets in the forward direction',                   category: 'Volume'      },
  { id: 3,  name: 'Total Backward Packets',           description: 'Number of packets in the backward direction',                  category: 'Volume'      },
  { id: 4,  name: 'Total Length of Forward Packets',  description: 'Total bytes sent in the forward direction',                    category: 'Volume'      },
  { id: 5,  name: 'Total Length of Backward Packets', description: 'Total bytes sent in the backward direction',                   category: 'Volume'      },
  { id: 6,  name: 'Forward Packet Length Mean',       description: 'Mean size of forward packets in bytes',                        category: 'Packet Size' },
  { id: 7,  name: 'Backward Packet Length Mean',      description: 'Mean size of backward packets in bytes',                       category: 'Packet Size' },
  { id: 8,  name: 'Packet Length Mean',               description: 'Mean length of all packets in the flow',                       category: 'Packet Size' },
  { id: 9,  name: 'Packet Length Std',                description: 'Standard deviation of packet lengths',                         category: 'Packet Size' },
  { id: 10, name: 'Packet Length Variance',           description: 'Variance in packet sizes across the flow',                     category: 'Packet Size' },
  { id: 11, name: 'Flow Bytes/s',                     description: 'Rate of bytes transferred per second',                         category: 'Rate'        },
  { id: 12, name: 'Flow Packets/s',                   description: 'Rate of packets transmitted per second',                       category: 'Rate'        },
  { id: 13, name: 'Flow IAT Mean',                    description: 'Mean inter-arrival time between flow packets',                  category: 'Timing'      },
  { id: 14, name: 'Flow IAT Std',                     description: 'Standard deviation of inter-arrival times',                    category: 'Timing'      },
  { id: 15, name: 'Forward IAT Mean',                 description: 'Mean inter-arrival time for forward packets',                   category: 'Timing'      },
  { id: 16, name: 'Backward IAT Mean',                description: 'Mean inter-arrival time for backward packets',                  category: 'Timing'      },
  { id: 17, name: 'Active Mean',                      description: 'Mean time a flow was active before going idle',                 category: 'Timing'      },
  { id: 18, name: 'FIN Flag Count',                   description: 'Number of packets with FIN flag set',                          category: 'Flags'       },
  { id: 19, name: 'SYN Flag Count',                   description: 'Number of packets with SYN flag set (connection initiations)', category: 'Flags'       },
  { id: 20, name: 'RST Flag Count',                   description: 'Number of packets with RST flag set (abrupt terminations)',    category: 'Flags'       },
];

const METRICS = [
  { label: 'Accuracy',  value: '99.70%', color: 'text-emerald-400', barColor: 'bg-emerald-400', bar: 99.70 },
  { label: 'Precision', value: '99.40%', color: 'text-cyan-400',    barColor: 'bg-cyan-400',    bar: 99.40 },
  { label: 'Recall',    value: '99.08%', color: 'text-violet-400',  barColor: 'bg-violet-400',  bar: 99.08 },
  { label: 'F1-Score',  value: '99.24%', color: 'text-amber-400',   barColor: 'bg-amber-400',   bar: 99.24 },
];

// Confusion matrix values from the actual training run (held-out test set, 424,171 samples)
const CM = {
  TP:  82_713,   // Malicious → correctly predicted Malicious
  TN: 340_188,   // Benign    → correctly predicted Benign
  FP:     500,   // Benign    → incorrectly predicted Malicious
  FN:     770,   // Malicious → incorrectly predicted Benign
};
const FPR = ((CM.FP / (CM.FP + CM.TN)) * 100).toFixed(2); // 0.15%

// Tuned decision threshold (from model/threshold.json — maximises F1 on validation set)
const THRESHOLD = 0.78;

const CATEGORY_COLORS: Record<string, string> = {
  Flow:           'bg-cyan-500/15 text-cyan-300 ring-1 ring-cyan-500/30',
  Volume:         'bg-violet-500/15 text-violet-300 ring-1 ring-violet-500/30',
  'Packet Size':  'bg-amber-500/15 text-amber-300 ring-1 ring-amber-500/30',
  Rate:           'bg-emerald-500/15 text-emerald-300 ring-1 ring-emerald-500/30',
  Timing:         'bg-blue-500/15 text-blue-300 ring-1 ring-blue-500/30',
  Flags:          'bg-red-500/15 text-red-300 ring-1 ring-red-500/30',
};

const ARCH_LAYERS = [
  { name: 'Input',         detail: 'Sliding window of 10 flows × 20 features',    color: 'border-slate-600 bg-slate-800/60'       },
  { name: 'Conv1D',        detail: '64 filters, kernel 3, padding 1, ReLU',       color: 'border-cyan-600/50 bg-cyan-900/20'       },
  { name: 'BiLSTM (×2)',   detail: '128 hidden × 2 directions, Dropout 0.3',      color: 'border-violet-600/50 bg-violet-900/20'   },
  { name: 'Last Timestep', detail: 'Take final BiLSTM output (1, 256)',           color: 'border-violet-600/30 bg-violet-900/10'   },
  { name: 'Dense',         detail: '256 → 64, ReLU, Dropout 0.5',                 color: 'border-amber-600/40 bg-amber-900/10'     },
  { name: 'Output',        detail: '64 → 2  (softmax: benign / malicious)',       color: 'border-emerald-600/50 bg-emerald-900/20' },
];

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function fmt(n: number) {
  return n.toLocaleString();
}

function SectionHeader({ icon: Icon, title, subtitle }: { icon: React.ElementType; title: string; subtitle?: string }) {
  return (
    <div className="flex items-start gap-3 mb-5">
      <div className="flex h-9 w-9 shrink-0 items-center justify-center rounded-lg bg-cyan-500/10 ring-1 ring-cyan-500/30 mt-0.5">
        <Icon className="h-5 w-5 text-cyan-400" />
      </div>
      <div>
        <h2 className="text-base font-semibold text-white">{title}</h2>
        {subtitle && <p className="text-sm text-slate-400 mt-0.5">{subtitle}</p>}
      </div>
    </div>
  );
}

// ---------------------------------------------------------------------------
// Confusion Matrix sub-component
// ---------------------------------------------------------------------------

function ConfusionMatrix() {
  const cells = [
    // [label, count, bg, text, ring, description]
    ['TN', CM.TN, 'bg-emerald-500/10', 'text-emerald-300', 'ring-emerald-500/30', 'Benign correctly identified'],
    ['FP', CM.FP, 'bg-orange-500/10',  'text-orange-300',  'ring-orange-500/30',  'Benign flagged as malicious'],
    ['FN', CM.FN, 'bg-red-500/10',     'text-red-300',     'ring-red-500/30',     'Malicious missed by model'],
    ['TP', CM.TP, 'bg-emerald-500/10', 'text-emerald-300', 'ring-emerald-500/30', 'Malicious correctly detected'],
  ] as const;

  return (
    <div>
      {/* axis labels */}
      <div className="flex mb-1">
        <div className="w-24 shrink-0" />
        <div className="flex-1 grid grid-cols-2 gap-2 text-center">
          <span className="text-xs font-semibold text-slate-400 uppercase tracking-wide">Predicted Benign</span>
          <span className="text-xs font-semibold text-slate-400 uppercase tracking-wide">Predicted Malicious</span>
        </div>
      </div>

      <div className="flex gap-2">
        {/* row labels */}
        <div className="w-24 shrink-0 grid grid-rows-2 gap-2">
          {['Actual Benign', 'Actual Malicious'].map((lbl) => (
            <div key={lbl} className="flex items-center justify-end pr-2">
              <span className="text-xs font-semibold text-slate-400 uppercase tracking-wide text-right leading-tight">
                {lbl}
              </span>
            </div>
          ))}
        </div>

        {/* 2×2 grid */}
        <div className="flex-1 grid grid-cols-2 grid-rows-2 gap-2">
          {cells.map(([abbr, count, bg, text, ring, desc]) => (
            <div
              key={abbr}
              className={`flex flex-col items-center justify-center rounded-xl border p-3 ${bg} ring-1 ${ring}`}
            >
              <span className={`text-[10px] font-bold uppercase tracking-widest ${text} mb-0.5`}>{abbr}</span>
              <span className={`text-xl font-bold ${text}`}>{fmt(count)}</span>
              <span className="text-[10px] text-slate-500 mt-0.5 text-center leading-tight">{desc}</span>
            </div>
          ))}
        </div>
      </div>
    </div>
  );
}

// ---------------------------------------------------------------------------
// Page
// ---------------------------------------------------------------------------

export function ModelPage() {
  const categories = [...new Set(FEATURES.map((f) => f.category))];

  return (
    <div className="space-y-6 max-w-6xl">
      {/* Page title */}
      <div>
        <h1 className="text-2xl font-bold text-white">AI Detection Model</h1>
        <p className="mt-1 text-sm text-slate-400">
          CNN-BiLSTM hybrid trained on CIC-IDS 2017 · 99.70% accuracy · 0.15% false positive rate.
        </p>
      </div>

      {/* Summary cards */}
      <div className="grid grid-cols-2 gap-4 sm:grid-cols-4">
        {[
          { label: 'Architecture',    value: 'CNN-BiLSTM',  icon: Brain,       color: 'text-cyan-400'    },
          { label: 'Input Features',  value: '20',          icon: Layers,      color: 'text-violet-400'  },
          { label: 'Training Windows',value: '~2.83M',      icon: Database,    color: 'text-amber-400'   },
          { label: 'Test Accuracy',   value: '99.70%',      icon: ShieldCheck, color: 'text-emerald-400' },
        ].map(({ label, value, icon: Icon, color }) => (
          <div key={label} className="rounded-xl border border-slate-800 bg-slate-900/60 p-4">
            <Icon className={`h-5 w-5 ${color} mb-2`} />
            <p className="text-xl font-bold text-white">{value}</p>
            <p className="text-xs text-slate-400 mt-0.5">{label}</p>
          </div>
        ))}
      </div>

      {/* Performance Metrics — full width */}
      <div className="rounded-xl border border-slate-800 bg-slate-900/60 p-5">
        <SectionHeader
          icon={TrendingUp}
          title="Performance Metrics"
          subtitle={`Evaluated on held-out test set · 424,171 windows · decision threshold ${THRESHOLD}`}
        />

        <div className="grid grid-cols-1 gap-8 lg:grid-cols-2">
          {/* Left: bar metrics + FPR */}
          <div className="space-y-4">
            {/* Metric bars */}
            <div className="space-y-3">
              {METRICS.map(({ label, value, color, barColor, bar }) => (
                <div key={label}>
                  <div className="flex justify-between text-sm mb-1">
                    <span className="text-slate-300 font-medium">{label}</span>
                    <span className={`font-bold ${color}`}>{value}</span>
                  </div>
                  <div className="h-1.5 w-full rounded-full bg-slate-800 overflow-hidden">
                    <div
                      className={`h-full rounded-full ${barColor}`}
                      style={{ width: `${bar}%` }}
                    />
                  </div>
                </div>
              ))}
            </div>

            {/* FPR highlight */}
            <div className="mt-2 rounded-lg border border-orange-500/25 bg-orange-500/8 px-4 py-3 flex items-center justify-between">
              <div>
                <p className="text-sm font-semibold text-white">False Positive Rate (FPR)</p>
                <p className="text-xs text-slate-400 mt-0.5">
                  FP / (FP + TN) · benign traffic incorrectly flagged
                </p>
              </div>
              <span className="text-2xl font-bold text-orange-300">{FPR}%</span>
            </div>

            {/* Derived counts legend */}
            <div className="grid grid-cols-2 gap-2 text-xs">
              {[
                { label: 'True Positives',  count: CM.TP, color: 'text-emerald-400' },
                { label: 'True Negatives',  count: CM.TN, color: 'text-emerald-400' },
                { label: 'False Positives', count: CM.FP, color: 'text-orange-400'  },
                { label: 'False Negatives', count: CM.FN, color: 'text-red-400'     },
              ].map(({ label, count, color }) => (
                <div key={label} className="flex items-center gap-2">
                  <span className={`font-bold ${color}`}>{fmt(count)}</span>
                  <span className="text-slate-500">{label}</span>
                </div>
              ))}
            </div>
          </div>

          {/* Right: confusion matrix */}
          <div>
            <p className="text-xs font-semibold uppercase tracking-wide text-slate-500 mb-3">Confusion Matrix</p>
            <ConfusionMatrix />
          </div>
        </div>
      </div>

      {/* Architecture + Dataset */}
      <div className="grid grid-cols-1 gap-6 lg:grid-cols-2">
        {/* Architecture */}
        <div className="rounded-xl border border-slate-800 bg-slate-900/60 p-5">
          <SectionHeader icon={Cpu} title="Model Architecture" subtitle="Hybrid CNN-BiLSTM pipeline" />
          <div className="space-y-2">
            {ARCH_LAYERS.map((layer, i) => (
              <div key={i} className={`flex items-center gap-3 rounded-lg border px-4 py-2.5 ${layer.color}`}>
                <span className="flex h-5 w-5 shrink-0 items-center justify-center rounded-full bg-slate-700 text-[10px] font-bold text-slate-300">
                  {i + 1}
                </span>
                <div className="min-w-0">
                  <p className="text-sm font-semibold text-white">{layer.name}</p>
                  <p className="text-xs text-slate-400 truncate">{layer.detail}</p>
                </div>
              </div>
            ))}
          </div>
        </div>

        {/* Dataset info */}
        <div className="rounded-xl border border-slate-800 bg-slate-900/60 p-5 flex flex-col">
          <SectionHeader icon={Database} title="Training Dataset" />

          <div className="flex flex-col gap-4 flex-1">
            {/* Key facts */}
            <dl className="space-y-3 text-sm">
              {[
                { term: 'Dataset',       def: 'CIC-IDS 2017' },
                { term: 'Source',        def: 'Canadian Institute for Cybersecurity (UNB)' },
                { term: 'Total windows', def: '2,827,807 sliding windows (10 flows each)' },
                { term: 'Window size',   def: '10 consecutive flows per sample' },
                { term: 'Preprocessing', def: 'StandardScaler fitted on training data only, class-weighted loss for imbalance' },
              ].map(({ term, def }) => (
                <div key={term} className="flex gap-3 border-b border-slate-800/60 pb-3 last:border-0 last:pb-0">
                  <dt className="w-32 shrink-0 text-slate-500 font-medium">{term}</dt>
                  <dd className="text-slate-300">{def}</dd>
                </div>
              ))}
            </dl>

            {/* Attack type badges */}
            <div>
              <p className="text-xs font-semibold uppercase tracking-wide text-slate-500 mb-2">Attack Types</p>
              <div className="flex flex-wrap gap-1.5">
                {['DoS', 'DDoS', 'PortScan', 'Brute Force', 'Web Attacks', 'Botnet', 'Infiltration'].map((a) => (
                  <span key={a} className="rounded-full bg-red-500/10 px-2.5 py-0.5 text-xs font-medium text-red-300 ring-1 ring-red-500/25">
                    {a}
                  </span>
                ))}
                <span className="rounded-full bg-emerald-500/10 px-2.5 py-0.5 text-xs font-medium text-emerald-300 ring-1 ring-emerald-500/25">
                  Benign
                </span>
              </div>
            </div>

            {/* Train / Val / Test split bar */}
            <div>
              <p className="text-xs font-semibold uppercase tracking-wide text-slate-500 mb-2">Dataset Split</p>
              <div className="flex h-5 w-full overflow-hidden rounded-full">
                <div className="flex items-center justify-center bg-cyan-500/70 text-[10px] font-bold text-white" style={{ width: '70%' }}>70%</div>
                <div className="flex items-center justify-center bg-violet-500/60 text-[10px] font-bold text-white" style={{ width: '15%' }}>15%</div>
                <div className="flex items-center justify-center bg-amber-500/60 text-[10px] font-bold text-white" style={{ width: '15%' }}>15%</div>
              </div>
              <div className="flex gap-4 mt-1.5 text-xs text-slate-400">
                <span className="flex items-center gap-1"><span className="h-2 w-2 rounded-full bg-cyan-500/70" />Train</span>
                <span className="flex items-center gap-1"><span className="h-2 w-2 rounded-full bg-violet-500/60" />Validation</span>
                <span className="flex items-center gap-1"><span className="h-2 w-2 rounded-full bg-amber-500/60" />Test</span>
              </div>
            </div>
          </div>
        </div>
      </div>

      {/* Training Configuration */}
      <div className="rounded-xl border border-slate-800 bg-slate-900/60 p-5">
        <SectionHeader
          icon={SettingsIcon}
          title="Training Configuration"
          subtitle="Hyperparameters and procedures used during training"
        />
        <div className="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-4 gap-3 text-sm">
          {[
            { k: 'Optimizer',         v: 'AdamW' },
            { k: 'Initial LR',        v: '1 × 10⁻³' },
            { k: 'Weight decay',      v: '1 × 10⁻⁴' },
            { k: 'LR scheduler',      v: 'ReduceLROnPlateau' },
            { k: 'Batch size',        v: '512' },
            { k: 'Loss',              v: 'Weighted CrossEntropy' },
            { k: 'Gradient clipping', v: 'Norm = 1.0' },
            { k: 'LSTM init',         v: 'Xavier + Orthogonal' },
            { k: 'Mixed precision',   v: 'AMP (float16)' },
            { k: 'Early stopping',    v: 'Patience 10' },
            { k: 'Epochs trained',    v: '23 (early stopped)' },
            { k: 'Decision threshold',v: `${THRESHOLD} (tuned by F1)` },
          ].map(({ k, v }) => (
            <div key={k} className="rounded-lg border border-slate-800 bg-slate-800/30 px-3 py-2">
              <p className="text-[10px] uppercase tracking-wide text-slate-500">{k}</p>
              <p className="text-sm font-semibold text-slate-200 mt-0.5">{v}</p>
            </div>
          ))}
        </div>
      </div>

      {/* Feature table */}
      <div className="rounded-xl border border-slate-800 bg-slate-900/60 p-5">
        <SectionHeader
          icon={FlaskConical}
          title="Input Features"
          subtitle="20 network-flow features extracted per connection"
        />

        {/* Category legend */}
        <div className="flex flex-wrap gap-2 mb-4">
          {categories.map((cat) => (
            <span key={cat} className={`rounded-full px-2.5 py-0.5 text-xs font-medium ${CATEGORY_COLORS[cat]}`}>
              {cat}
            </span>
          ))}
        </div>

        <div className="overflow-x-auto">
          <table className="w-full text-sm">
            <thead>
              <tr className="border-b border-slate-800">
                <th className="text-left py-2 pr-4 text-xs font-semibold uppercase tracking-wide text-slate-500 w-8">#</th>
                <th className="text-left py-2 pr-6 text-xs font-semibold uppercase tracking-wide text-slate-500">Feature</th>
                <th className="text-left py-2 pr-4 text-xs font-semibold uppercase tracking-wide text-slate-500">Category</th>
                <th className="text-left py-2 text-xs font-semibold uppercase tracking-wide text-slate-500">Description</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-800/60">
              {FEATURES.map(({ id, name, description, category }) => (
                <tr key={id} className="hover:bg-slate-800/30 transition-colors">
                  <td className="py-2.5 pr-4 text-slate-600 font-mono text-xs">{String(id).padStart(2, '0')}</td>
                  <td className="py-2.5 pr-6 font-medium text-slate-200 whitespace-nowrap">{name}</td>
                  <td className="py-2.5 pr-4">
                    <span className={`rounded-full px-2 py-0.5 text-xs font-medium ${CATEGORY_COLORS[category]}`}>
                      {category}
                    </span>
                  </td>
                  <td className="py-2.5 text-slate-400">{description}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
}
