// Runs the analysis off the main thread so the page stays responsive on slow devices.
import { runJob } from './job.js';

self.onmessage = (ev) => {
  const { id, job } = ev.data;
  try { self.postMessage({ id, result: runJob(job) }); }
  catch (e) { self.postMessage({ id, error: e.message }); }
};
