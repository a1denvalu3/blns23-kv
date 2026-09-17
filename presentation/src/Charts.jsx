import React, { useMemo } from 'react';
import {
  ResponsiveContainer, BarChart, Bar, XAxis, YAxis, CartesianGrid,
  Tooltip, LabelList, Cell,
} from 'recharts';

const DARK = '#1c1028';
const MUTED = '#80708f';
const BORDER = '#dbd6e1';
const CAT = ['#4e79a7', '#f28e2b', '#e15759', '#76b7b2', '#59a14f', '#edc948'];
const SEM_GREEN = '#2ba185';
const SEM_RED = '#f55459';
const SEM_AMBER = '#d4953a';

const ax = {
  axisLine: { stroke: BORDER },
  tickLine: false,
  tick: { fill: MUTED, fontSize: 11, fontFamily: 'Rubik, system-ui' },
};
const grid = { strokeDasharray: '3 3', stroke: '#f0edf3', vertical: false };
const tipStyle = {
  background: '#fff', border: `1px solid ${BORDER}`, borderRadius: 6,
  fontSize: 12, fontFamily: 'Rubik, system-ui',
};
const fmt = (n) => n.toLocaleString('en-US');

// Wire sizes from the construction's efficiency table (κ = 512).
export function WireBreakdown() {
  const data = useMemo(() => ([
    { name: 'Aggregate commitment c_agg', bytes: 113088 },
    { name: '512 opened seeds', bytes: 16384 },
    { name: '512 unopened leaf hashes', bytes: 16384 },
    { name: 'Session identifier', bytes: 32 },
  ]), []);
  return (
    <ResponsiveContainer width="100%" height={220}>
      <BarChart data={data} layout="vertical" margin={{ left: 10, right: 70, top: 4, bottom: 4 }}>
        <CartesianGrid {...grid} horizontal={false} vertical />
        <XAxis type="number" {...ax} tickFormatter={(v) => `${Math.round(v / 1024)} KiB`} domain={[0, 120000]} />
        <YAxis type="category" dataKey="name" {...ax} width={190} />
        <Tooltip contentStyle={tipStyle} formatter={(v) => [`${fmt(v)} B`, 'Size']} />
        <Bar dataKey="bytes" radius={[0, 3, 3, 0]}>
          {data.map((_, i) => <Cell key={i} fill={CAT[i]} />)}
          <LabelList dataKey="bytes" position="right" formatter={fmt}
            style={{ fill: DARK, fontSize: 11, fontFamily: 'Rubik, system-ui' }} />
        </Bar>
      </BarChart>
    </ResponsiveContainer>
  );
}

export function MessageSizes() {
  const data = useMemo(() => ([
    { name: 'First message (user → signer)', bytes: 145888 },
    { name: 'Credential (presentation)', bytes: 32784 },
    { name: 'Response h (signer → user)', bytes: 1216 },
  ]), []);
  return (
    <ResponsiveContainer width="100%" height={220}>
      <BarChart data={data} layout="vertical" margin={{ left: 10, right: 70, top: 4, bottom: 4 }}>
        <CartesianGrid {...grid} horizontal={false} vertical />
        <XAxis type="number" {...ax} tickFormatter={(v) => `${Math.round(v / 1024)} KiB`} domain={[0, 160000]} />
        <YAxis type="category" dataKey="name" {...ax} width={190} />
        <Tooltip contentStyle={tipStyle} formatter={(v) => [`${fmt(v)} B`, 'Size']} />
        <Bar dataKey="bytes" radius={[0, 3, 3, 0]}>
          {data.map((_, i) => <Cell key={i} fill={CAT[i]} />)}
          <LabelList dataKey="bytes" position="right" formatter={fmt}
            style={{ fill: DARK, fontSize: 11, fontFamily: 'Rubik, system-ui' }} />
        </Bar>
      </BarChart>
    </ResponsiveContainer>
  );
}

// Attack work factors (log2) from the security analysis, κ = 512.
export function AttackCosts() {
  const data = useMemo(() => ([
    { name: 'Balanced splice (classical)', log2work: 256, note: 'cheapest known — sets the floor', color: SEM_RED },
    { name: 'Balanced splice (quantum, generic)', log2work: 128, note: 'post-quantum margin', color: SEM_AMBER },
    { name: 'Unit-vector key recovery (aiming)', log2work: 499, note: '≈ 2^(κ−13) via density pricing', color: SEM_GREEN },
    { name: 'Wagner k-tree sum-to-target', log2work: 90470, note: 'blocked by the 904,704-bit sum space', color: SEM_GREEN },
  ]), []);
  return (
    <ResponsiveContainer width="100%" height={280}>
      <BarChart data={data} layout="vertical" margin={{ left: 10, right: 90, top: 4, bottom: 4 }}>
        <CartesianGrid {...grid} horizontal={false} vertical />
        <XAxis type="number" {...ax} domain={[0, 95000]}
          tickFormatter={(v) => `2^${fmt(v)}`} />
        <YAxis type="category" dataKey="name" {...ax} width={220} />
        <Tooltip contentStyle={tipStyle}
          formatter={(v, _n, item) => [`2^${fmt(v)} work — ${item.payload.note}`, '']} />
        <Bar dataKey="log2work" radius={[0, 3, 3, 0]}>
          {data.map((d, i) => <Cell key={i} fill={d.color} />)}
          <LabelList dataKey="log2work" position="right" formatter={(v) => `2^${fmt(v)}`}
            style={{ fill: DARK, fontSize: 11, fontFamily: 'Rubik, system-ui' }} />
        </Bar>
      </BarChart>
    </ResponsiveContainer>
  );
}
