// Vercel serverless function — same-origin tile proxy.
// Fetches map tiles server-side so the browser can draw them to canvas
// without any CORS restrictions (required for DXF aerial export).
export default async function handler(req, res) {
  const { url } = req.query;
  if (!url) { res.status(400).end(); return; }

  // Allowlist: only known map tile hosts
  const ALLOWED = [
    'arcgisonline.com',
    'openstreetmap.org',
    'tile.googleapis.com',
    'mt0.google.com','mt1.google.com','mt2.google.com','mt3.google.com',
    'ecn.t0.tiles.virtualearth.net','ecn.t1.tiles.virtualearth.net',
    'ecn.t2.tiles.virtualearth.net','ecn.t3.tiles.virtualearth.net',
    'wayback.maptiles.arcgis.com'
  ];

  let parsed;
  try { parsed = new URL(url); } catch(e) { res.status(400).end(); return; }
  if (!ALLOWED.some(h => parsed.hostname.endsWith(h))) {
    res.status(403).end(); return;
  }

  try {
    const upstream = await fetch(url, {
      headers: {
        'User-Agent': 'PLasaldeTurnSimulator/1.0 (+https://plasalde-turn-sim.vercel.app)'
      }
    });
    if (!upstream.ok) { res.status(upstream.status).end(); return; }

    const buf = await upstream.arrayBuffer();
    res.setHeader('Content-Type', upstream.headers.get('content-type') || 'image/jpeg');
    res.setHeader('Cache-Control', 'public, max-age=3600, s-maxage=86400');
    res.setHeader('Access-Control-Allow-Origin', '*');
    res.send(Buffer.from(buf));
  } catch(e) {
    res.status(502).end();
  }
}
