/**
 * Isolation Forest (Liu, Ting & Zhou, 2008), implemented from scratch.
 *
 * Anomalies are few and different, so random splits isolate them in fewer steps.
 * Score s(x) = 2^(-E[h(x)] / c(n)), where h is the path length, n the sample size
 * and c(n) the average path length of an unsuccessful binary-search-tree lookup.
 * s close to 1 means anomalous; well below 0.5 means normal.
 */
import { mulberry32 } from './rng.js';

const EULER = 0.5772156649;
export const cFactor = (n) => (n <= 1 ? 0 : 2 * (Math.log(n - 1) + EULER) - (2 * (n - 1)) / n);

function buildTree(rows, depth, maxDepth, rand, nFeat) {
  if (depth >= maxDepth || rows.length <= 1) return { size: rows.length };
  // Pick a feature that actually varies in this node.
  const order = Array.from({ length: nFeat }, (_, i) => i);
  for (let i = order.length - 1; i > 0; i--) { const j = Math.floor(rand() * (i + 1)); [order[i], order[j]] = [order[j], order[i]]; }
  for (const f of order) {
    let lo = Infinity, hi = -Infinity;
    for (const r of rows) { if (r[f] < lo) lo = r[f]; if (r[f] > hi) hi = r[f]; }
    if (hi > lo) {
      const split = lo + rand() * (hi - lo);
      const left = [], right = [];
      for (const r of rows) (r[f] < split ? left : right).push(r);
      return { f, split, left: buildTree(left, depth + 1, maxDepth, rand, nFeat), right: buildTree(right, depth + 1, maxDepth, rand, nFeat) };
    }
  }
  return { size: rows.length };
}

function pathLength(x, node, depth) {
  while (node.f !== undefined) { node = x[node.f] < node.split ? node.left : node.right; depth++; }
  return depth + cFactor(node.size);
}

export class IsolationForest {
  constructor({ trees = 150, sampleSize = 256, seed = 42 } = {}) {
    this.trees = trees; this.sampleSize = sampleSize; this.seed = seed; this.forest = [];
  }

  fit(X) {
    if (!X.length) throw new Error('Isolation Forest needs at least one training row.');
    const rand = mulberry32(this.seed);
    const n = Math.min(this.sampleSize, X.length);
    const maxDepth = Math.ceil(Math.log2(Math.max(2, n)));
    this.n = n; this.nFeat = X[0].length; this.forest = [];
    for (let t = 0; t < this.trees; t++) {
      const sample = [];
      for (let i = 0; i < n; i++) sample.push(X[Math.floor(rand() * X.length)]);
      this.forest.push(buildTree(sample, 0, maxDepth, rand, this.nFeat));
    }
    return this;
  }

  /** Anomaly score in (0, 1]. */
  score(x) {
    let total = 0;
    for (const tree of this.forest) total += pathLength(x, tree, 0);
    return Math.pow(2, -(total / this.forest.length) / cFactor(this.n));
  }
}
