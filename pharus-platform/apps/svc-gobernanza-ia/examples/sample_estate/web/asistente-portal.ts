// Asistente del portal de pacientes (Vertex AI / Gemini vía REST, como WizardAI).
const URL = `https://us-central1-aiplatform.googleapis.com/v1/projects/${process.env.GCP_PROYECTO}/locations/us-central1/publishers/google/models/gemini-2.5-flash:generateContent`;

export async function responder(pregunta: string, email: string): Promise<string> {
  const r = await fetch(URL, {
    method: 'POST',
    headers: { Authorization: `Bearer ${process.env.IA_TOKEN}` },
    body: JSON.stringify({ model: 'gemini-2.5-flash', contents: [{ role: 'user', parts: [{ text: pregunta }] }] }),
  });
  return (await r.json()).candidates[0].content.parts[0].text;
}
