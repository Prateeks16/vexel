// Structured editor for an app's ordered policy list. It keeps its own state
// and only re-renders on structural changes, so typing never loses focus.

import { h } from './dom.js';

const SELECTORS = [
  ['email_domain', 'Email domain', 'example.com'],
  ['email', 'Email', 'alice@example.com'],
  ['group', 'Group', 'caseworkers'],
  ['ip_range', 'IP range', '203.0.113.0/24'],
  ['trusted_device', 'Trusted device', ''],
  ['everyone', 'Everyone', ''],
];

// Selectors that take no value.
const FLAGS = { everyone: 'Matches every signed-in user', trusted_device: 'User is on one of their enrolled company devices' };

const GROUPS = [
  ['include', 'Include — any of'],
  ['require', 'Require — all of'],
  ['exclude', 'Exclude — none of'],
];

function toRule(r) {
  const [type] = SELECTORS.find(([t]) => r[t] !== undefined) || ['email_domain'];
  return { type, value: type in FLAGS ? '' : String(r[type] ?? '') };
}

function fromRule({ type, value }) {
  return type in FLAGS ? { [type]: true } : { [type]: value.trim() };
}

export function policyEditor(initial) {
  const state = (initial || []).map((p) => ({
    name: p.name || '',
    action: p.action || 'allow',
    include: (p.include || []).map(toRule),
    require: (p.require || []).map(toRule),
    exclude: (p.exclude || []).map(toRule),
  }));
  const list = h('div');

  const rerender = () => list.replaceChildren(...state.map(renderPolicy));

  function renderRule(rules, i) {
    const rule = rules[i];
    const meta = SELECTORS.find(([t]) => t === rule.type);
    const select = h('select', { 'aria-label': 'Match on', onchange: (e) => { rule.type = e.target.value; rerender(); } },
      SELECTORS.map(([t, label]) => h('option', { value: t, selected: t === rule.type }, label)));
    const input = rule.type in FLAGS
      ? h('span', { class: 'everyone' }, FLAGS[rule.type])
      : h('input', { type: 'text', required: true, value: rule.value, placeholder: meta[2], 'aria-label': meta[1], oninput: (e) => { rule.value = e.target.value; } });
    return h('div', { class: 'rule' }, select, input,
      h('button', { type: 'button', class: 'btn btn-ghost btn-sm', 'aria-label': 'Remove rule', onclick: () => { rules.splice(i, 1); rerender(); } }, '✕'));
  }

  function renderPolicy(p, i) {
    const move = (d) => {
      const j = i + d;
      if (j < 0 || j >= state.length) return;
      [state[i], state[j]] = [state[j], state[i]];
      rerender();
    };
    return h('div', { class: 'policy' },
      h('div', { class: 'policy-top' },
        h('span', { class: 'policy-order', title: 'Evaluation order' }, String(i + 1)),
        h('input', { type: 'text', required: true, value: p.name, placeholder: 'Policy name', 'aria-label': 'Policy name', oninput: (e) => { p.name = e.target.value; } }),
        h('select', { 'aria-label': 'Action', onchange: (e) => { p.action = e.target.value; } },
          h('option', { value: 'allow', selected: p.action === 'allow' }, 'Allow'),
          h('option', { value: 'deny', selected: p.action === 'deny' }, 'Deny')),
        h('button', { type: 'button', class: 'btn btn-ghost btn-sm', 'aria-label': 'Move up', disabled: i === 0, onclick: () => move(-1) }, '↑'),
        h('button', { type: 'button', class: 'btn btn-ghost btn-sm', 'aria-label': 'Move down', disabled: i === state.length - 1, onclick: () => move(1) }, '↓'),
        h('button', { type: 'button', class: 'btn btn-ghost btn-sm btn-danger', 'aria-label': 'Delete policy', onclick: () => { state.splice(i, 1); rerender(); } }, '✕')),
      GROUPS.map(([key, title]) => h('div', { class: 'rule-group' },
        h('div', { class: 'rule-group-title' }, title),
        p[key].map((_, j) => renderRule(p[key], j)),
        h('button', { type: 'button', class: 'btn btn-ghost btn-sm', onclick: () => { p[key].push({ type: 'email_domain', value: '' }); rerender(); } }, '+ Add rule'))));
  }

  rerender();
  const el = h('div', null,
    h('div', { class: 'policies-head' },
      h('h3', null, 'Access policies'),
      h('button', { type: 'button', class: 'btn btn-sm', onclick: () => {
        state.push({ name: '', action: 'allow', include: [{ type: 'email_domain', value: '' }], require: [], exclude: [] });
        rerender();
      } }, '+ Add policy')),
    h('p', { class: 'hint muted small' }, 'Checked top to bottom; the first matching policy decides. If none match, access is denied.'),
    list);

  return {
    el,
    value: () => state.map((p) => ({
      name: p.name.trim(),
      action: p.action,
      include: p.include.map(fromRule),
      require: p.require.map(fromRule),
      exclude: p.exclude.map(fromRule),
    })),
  };
}
