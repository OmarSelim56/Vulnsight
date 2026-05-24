import {
  Brain,
  Cpu,
  Database,
  FlaskConical,
  Layers,
  Settings as SettingsIcon,
  ShieldCheck,
  TrendingUp,
} from 'lucide-react';

// ---------------------------------------------------------------------------
// Data — values reflect the actual most-recent training run with the
// 34 tool-agnostic feature set (PowerTransformer + StandardScaler pipeline,
// Focal Loss, Cosine LR + warmup, BatchNorm + Attention model).
// ---------------------------------------------------------------------------

const FEATURES = [
  { id: 1,  name: 'Destination Port',              description: 'Server-side port — strong signal for service-targeted attacks',  category: 'Flow'        },
  // Volume — packet/byte counts per direction
  { id: 2,  name: 'Total Fwd Packets',             description: 'Number of packets sent in the forward (client→server) direction', category: 'Volume'      },
  { id: 3,  name: 'Total Backward Packets',        description: 'Number of packets returned in the backward direction',            category: 'Volume'      },
  { id: 4,  name: 'Total Length of Fwd Packets',   description: 'Total bytes sent in the forward direction',                       category: 'Volume'      },
  { id: 5,  name: 'Total Length of Bwd Packets',   description: 'Total bytes received in the backward direction',                  category: 'Volume'      },
  // Forward packet size distribution
  { id: 6,  name: 'Fwd Packet Length Max',         description: 'Largest packet in the forward direction',                         category: 'Packet Size' },
  { id: 7,  name: 'Fwd Packet Length Min',         description: 'Smallest packet in the forward direction',                        category: 'Packet Size' },
  { id: 8,  name: 'Fwd Packet Length Mean',        description: 'Mean forward packet size',                                        category: 'Packet Size' },
  { id: 9,  name: 'Fwd Packet Length Std',         description: 'Standard deviation of forward packet sizes',                      category: 'Packet Size' },
  // Backward packet size distribution
  { id: 10, name: 'Bwd Packet Length Max',         description: 'Largest packet in the backward direction',                        category: 'Packet Size' },
  { id: 11, name: 'Bwd Packet Length Min',         description: 'Smallest packet in the backward direction',                       category: 'Packet Size' },
  { id: 12, name: 'Bwd Packet Length Mean',        description: 'Mean backward packet size',                                       category: 'Packet Size' },
  { id: 13, name: 'Bwd Packet Length Std',         description: 'Standard deviation of backward packet sizes',                     category: 'Packet Size' },
  // Bidirectional packet size distribution
  { id: 14, name: 'Min Packet Length',             description: 'Smallest packet seen in the entire flow',                         category: 'Packet Size' },
  { id: 15, name: 'Max Packet Length',             description: 'Largest packet seen in the entire flow',                          category: 'Packet Size' },
  { id: 16, name: 'Packet Length Mean',            description: 'Mean packet length across both directions',                       category: 'Packet Size' },
  { id: 17, name: 'Packet Length Std',             description: 'Standard deviation of packet lengths',                            category: 'Packet Size' },
  { id: 18, name: 'Packet Length Variance',        description: 'Variance of packet lengths (signal of payload uniformity)',       category: 'Packet Size' },
  // Bidirectional TCP flag counts
  { id: 19, name: 'FIN Flag Count',                description: 'Packets with FIN flag set — graceful termination indicator',       category: 'Flags'       },
  { id: 20, name: 'SYN Flag Count',                description: 'Packets with SYN flag — high counts indicate scans / floods',     category: 'Flags'       },
  { id: 21, name: 'RST Flag Count',                description: 'Packets with RST flag — abrupt terminations / refused connections', category: 'Flags'     },
  { id: 22, name: 'PSH Flag Count',                description: 'Packets with PSH flag — pushes data through TCP buffer',          category: 'Flags'       },
  { id: 23, name: 'ACK Flag Count',                description: 'Packets with ACK flag — normal acknowledgement traffic',          category: 'Flags'       },
  { id: 24, name: 'URG Flag Count',                description: 'Packets with URG flag — rarely seen, anomaly indicator',          category: 'Flags'       },
  { id: 25, name: 'CWE Flag Count',                description: 'Packets with CWR flag — TCP congestion window reduction',         category: 'Flags'       },
  { id: 26, name: 'ECE Flag Count',                description: 'Packets with ECE flag — explicit congestion echo',                category: 'Flags'       },
  // Directional PSH / URG flag counts
  { id: 27, name: 'Fwd PSH Flags',                 description: 'PSH flags in the forward direction (client pushes)',              category: 'Flags'       },
  { id: 28, name: 'Bwd PSH Flags',                 description: 'PSH flags in the backward direction (server pushes)',             category: 'Flags'       },
  { id: 29, name: 'Fwd URG Flags',                 description: 'URG flags in the forward direction',                              category: 'Flags'       },
  { id: 30, name: 'Bwd URG Flags',                 description: 'URG flags in the backward direction',                             category: 'Flags'       },
  // Derived ratios / averages
  { id: 31, name: 'Down/Up Ratio',                 description: 'Backward bytes ÷ forward bytes — exfil = low ratio, download = high', category: 'Derived' },
  { id: 32, name: 'Average Packet Size',           description: 'Total bytes ÷ total packets across the flow',                     category: 'Derived'     },
  { id: 33, name: 'Avg Fwd Segment Size',          description: 'Mean forward TCP segment size',                                   category: 'Derived'     },
  { id: 34, name: 'Avg Bwd Segment Size',          description: 'Mean backward TCP segment size',                                  category: 'Derived'     },
];

const METRICS = [
  { label: 'Accuracy',  value: '99.85%', color: 'text-emerald-400', barColor: 'bg-emerald-400', bar: 99.85 },
  { label: 'Precision', value: '99.60%', color: 'text-cyan-400',    barColor: 'bg-cyan-400',    bar: 99.60 },
  { label: 'Recall',    value: '99.61%', color: 'text-violet-400',  barColor: 'bg-violet-400',  bar: 99.61 },
  { label: 'F1-Score',  value: '99.61%', color: 'text-amber-400',   barColor: 'bg-amber-400',   bar: 99.61 },
];

// Confusion matrix from the latest training run (held-out test set, 424,601 samples)
const CM = {
  TP:  83_323,   // Malicious → correctly predicted Malicious
  TN: 340_621,   // Benign    → correctly predicted Benign
  FP:     333,   // Benign    → incorrectly predicted Malicious
  FN:     324,   // Malicious → incorrectly predicted Benign
};
const FPR = ((CM.FP / (CM.FP + CM.TN)) * 100).toFixed(3); // 0.098%

const TEST_SIZE = CM.TP + CM.TN + CM.FP + CM.FN; // 424,601

// Tuned decision threshold (from model/threshold.json — maximises F1 on validation set)
const THRESHOLD = 0.76;

const CATEGORY_COLORS: Record<string, string> = {
  Flow:          'bg-cyan-500/15 text-cyan-300 ring-1 ring-cyan-500/30',
  Volume:        'bg-violet-500/15 text-violet-300 ring-1 ring-violet-500/30',
  'Packet Size': 'bg-amber-500/15 text-amber-300 ring-1 ring-amber-500/30',
  Flags:         'bg-red-500/15 text-red-300 ring-1 ring-red-500/30',
  Derived:       'bg-emerald-500/15 text-emerald-300 ring-1 ring-emerald-500/30',
};

const ARCH_LAYERS = [
  { name: 'Input',             detail: 'Sliding window of 10 flows × 34 features',         color: 'border-slate-600 bg-slate-800/60'       },
  { name: 'Conv1D + BatchNorm',detail: '34→64 filters, kernel 3, ReLU',                    color: 'border-cyan-600/50 bg-cyan-900/20'      },
  { name: 'Conv1D + BatchNorm',detail: '64→64 filters, kernel 3, ReLU (richer local features)', color: 'border-cyan-600/40 bg-cyan-900/15'  },
  { name: 'BiLSTM (×2)',       detail: '128 hidden × 2 directions, Dropout 0.3',           color: 'border-violet-600/50 bg-violet-900/20'  },
  { name: 'LayerNorm',         detail: 'Normalise BiLSTM output (256-dim per timestep)',   color: 'border-violet-600/30 bg-violet-900/10'  },
  { name: 'Attention Pooling', detail: 'Additive attention — learns which of 10 flows matter most', color: 'border-blue-600/50 bg-blue-900/20' },
  { name: 'Dense',             detail: '256 → 64, ReLU, Dropout 0.5',                      color: 'border-amber-600/40 bg-amber-900/10'    },
  { name: 'Output',            detail: '64 → 2  (softmax: benign / malicious)',            color: 'border-emerald-600/50 bg-emerald-900/20'},
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
              <span className="text-xl font-bold text-white">{fmt(count)}</span>
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
    <div className="space-y-6">
      {/* Page title */}
      <div>
        <h1 className="text-2xl font-bold text-white">AI Detection Model</h1>
        <p className="mt-1 text-sm text-slate-400">
          CNN-BiLSTM hybrid · trained on CIC-IDS 2017 · 99.85% accuracy · 0.098% false positive rate
        </p>
      </div>

      {/* Summary cards */}
      <div className="grid grid-cols-2 gap-4 sm:grid-cols-4">
        {[
          { label: 'Architecture',     value: 'CNN-BiLSTM',             icon: Brain,       color: 'text-cyan-400'    },
          { label: 'Input Features',   value: '34',                      icon: Layers,      color: 'text-violet-400'  },
          { label: 'Training Windows', value: '~2.83M',                  icon: Database,    color: 'text-amber-400'   },
          { label: 'Test Accuracy',    value: '99.85%',                  icon: ShieldCheck, color: 'text-emerald-400' },
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
          subtitle={`Evaluated on held-out test set · ${fmt(TEST_SIZE)} windows · decision threshold ${THRESHOLD}`}
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
          <SectionHeader icon={Cpu} title="Model Architecture" subtitle="CNN-BiLSTM with BatchNorm and additive attention" />
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
          <p className="mt-4 text-xs text-slate-500 leading-relaxed">
            <span className="font-semibold text-slate-400">663,235 trainable parameters.</span>{' '}
            Per-conversation 10-flow buffers at inference time, so each (src,dst) tuple
            gets its own context window instead of mixing concurrent unrelated traffic.
          </p>
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
                { term: 'Total windows', def: '2,830,671 sliding windows (10 flows each)' },
                { term: 'Window size',   def: '10 consecutive flows per sample' },
                { term: 'Feature set',   def: '34 tool-agnostic features (count, byte, flag, derived)' },
                { term: 'Preprocessing', def: 'PowerTransformer (Yeo-Johnson) → StandardScaler pipeline, fitted on training set only' },
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
                {['DDoS', 'DoS Hulk', 'DoS GoldenEye', 'DoS Slowloris', 'DoS Slowhttptest', 'PortScan', 'FTP-Patator', 'SSH-Patator', 'Web Attacks', 'Bot', 'Infiltration', 'Heartbleed'].map((a) => (
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
                <span className="flex items-center gap-1"><span className="h-2 w-2 rounded-full bg-cyan-500/70" />Train (1.98M)</span>
                <span className="flex items-center gap-1"><span className="h-2 w-2 rounded-full bg-violet-500/60" />Validation (424k)</span>
                <span className="flex items-center gap-1"><span className="h-2 w-2 rounded-full bg-amber-500/60" />Test (424k)</span>
              </div>
              <p className="mt-2 text-xs text-slate-500">
                Stratified by attack type — test set contains balanced representation of each class.
              </p>
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
            { k: 'LR scheduler',      v: 'Cosine + 3-epoch warmup' },
            { k: 'Batch size',        v: '512' },
            { k: 'Loss',              v: 'Focal Loss (γ=2.0) + label smoothing (0.05)' },
            { k: 'Class weights',     v: 'Balanced (benign 0.62, attack 2.54)' },
            { k: 'Gradient clipping', v: 'Norm = 1.0' },
            { k: 'LSTM init',         v: 'Xavier + Orthogonal + forget bias 1' },
            { k: 'Mixed precision',   v: 'AMP (float16)' },
            { k: 'SWA',               v: 'Stochastic Weight Averaging enabled' },
            { k: 'Early stopping',    v: 'Patience 12' },
            { k: 'Epochs trained',    v: '26 (early stopped)' },
            { k: 'Decision threshold',v: `${THRESHOLD} (tuned by F1 on validation)` },
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
          subtitle="34 tool-agnostic network-flow features extracted per connection"
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
