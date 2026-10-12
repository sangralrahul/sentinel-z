/**
 * City coordinates used for impossible-travel checks. Only city names are needed,
 * never precise locations, which keeps location data coarse by design.
 */
export const CITIES = {
  Mumbai: [19.076, 72.8777], Delhi: [28.6139, 77.209], Bengaluru: [12.9716, 77.5946], Hyderabad: [17.385, 78.4867],
  Chennai: [13.0827, 80.2707], Kolkata: [22.5726, 88.3639], Pune: [18.5204, 73.8567], Ahmedabad: [23.0225, 72.5714],
  Jaipur: [26.9124, 75.7873], Lucknow: [26.8467, 80.9462], Kochi: [9.9312, 76.2673], Chandigarh: [30.7333, 76.7794],
  Bhopal: [23.2599, 77.4126], Patna: [25.5941, 85.1376], Guwahati: [26.1445, 91.7362], Indore: [22.7196, 75.8577],
  Dubai: [25.2048, 55.2708], Singapore: [1.3521, 103.8198], London: [51.5074, -0.1278], Frankfurt: [50.1109, 8.6821],
  'New York': [40.7128, -74.006], Lagos: [6.5244, 3.3792], Moscow: [55.7558, 37.6173], 'São Paulo': [-23.5505, -46.6333]
};

/** Great-circle distance in km between two cities, or null if either is unknown. */
export function distanceKm(a, b) {
  const p = CITIES[a], q = CITIES[b];
  if (!p || !q) return null;
  if (a === b) return 0;
  const R = 6371, toRad = (d) => (d * Math.PI) / 180;
  const dLat = toRad(q[0] - p[0]), dLon = toRad(q[1] - p[1]);
  const h = Math.sin(dLat / 2) ** 2 + Math.cos(toRad(p[0])) * Math.cos(toRad(q[0])) * Math.sin(dLon / 2) ** 2;
  return 2 * R * Math.asin(Math.sqrt(h));
}
