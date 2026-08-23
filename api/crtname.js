// Vercel Serverless Function — proxies crt.name on the server side.
// Server-side fetch has no CORS restrictions and no mixed-content blocks.
export default async function handler(req, res) {
    const { domain } = req.query;

    if (!domain) {
        return res.status(400).json({ error: 'Missing domain parameter' });
    }

    try {
        const response = await fetch(`http://crt.name/v1/search?apex=${domain}`);

        if (!response.ok) {
            return res.status(response.status).json({ error: `crt.name returned ${response.status}` });
        }

        const text = await response.text();

        res.setHeader('Access-Control-Allow-Origin', '*');
        res.setHeader('Content-Type', 'text/plain');
        return res.status(200).send(text);
    } catch (e) {
        return res.status(500).json({ error: e.message });
    }
}
