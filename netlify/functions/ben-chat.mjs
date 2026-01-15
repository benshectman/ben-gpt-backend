export default async (request, context) => {
  const allowedOrigin = process.env.ALLOWED_ORIGIN || "*";

  if (request.method === "OPTIONS") {
    return new Response(null, {
      status: 204,
      headers: {
        "Access-Control-Allow-Origin": allowedOrigin,
        "Access-Control-Allow-Methods": "POST, OPTIONS",
        "Access-Control-Allow-Headers": "Content-Type",
      },
    });
  }

  if (request.method !== "POST") {
    return new Response(JSON.stringify({ error: "Use POST" }), {
      status: 405,
      headers: {
        "Content-Type": "application/json",
        "Access-Control-Allow-Origin": allowedOrigin,
      },
    });
  }

  try {
    const { message, conversation } = await request.json();

    if (!process.env.OPENAI_API_KEY) {
      return new Response(JSON.stringify({ error: "Missing OPENAI_API_KEY" }), {
        status: 500,
        headers: {
          "Content-Type": "application/json",
          "Access-Control-Allow-Origin": allowedOrigin,
        },
      });
    }

    // Lightweight input limits to reduce cost and abuse.
    const safeMessage = String(message || "").slice(0, 2000);
    if (!safeMessage.trim()) {
      return new Response(JSON.stringify({ error: "Empty message" }), {
        status: 400,
        headers: {
          "Content-Type": "application/json",
          "Access-Control-Allow-Origin": allowedOrigin,
        },
      });
    }

    // Minimal “Ben GPT” system instruction. You will replace this later with your real policy + knowledge retrieval.
    const system = [
      "You are a conversational representation of Ben for a public website.",
      "Answer only with professional, public information. If you do not know, say so.",
      "Do not invent facts about Ben. Do not provide private personal details.",
      "Keep responses concise unless the user asks for depth.",
    ].join(" ");

    const resp = await fetch("https://api.openai.com/v1/responses", {
      method: "POST",
      headers: {
        "Authorization": `Bearer ${process.env.OPENAI_API_KEY}`,
        "Content-Type": "application/json",
      },
      body: JSON.stringify({
        // Pick a model you have access to. You can change this later.
        model: "gpt-4.1-mini",
        input: [
          { role: "system", content: system },
          { role: "user", content: safeMessage },
        ],
      }),
    });

    if (!resp.ok) {
      const errText = await resp.text();
      return new Response(JSON.stringify({ error: "OpenAI error", details: errText }), {
        status: 502,
        headers: {
          "Content-Type": "application/json",
          "Access-Control-Allow-Origin": allowedOrigin,
        },
      });
    }

    const data = await resp.json();

    // The Responses API returns output in structured chunks.
    // This extraction is defensive and works for common text outputs.
    const answer =
      data.output_text ||
      data.output?.map(o => o.content?.map(c => c.text).join("")).join("\n") ||
      "No text returned.";

    return new Response(JSON.stringify({ answer }), {
      status: 200,
      headers: {
        "Content-Type": "application/json",
        "Access-Control-Allow-Origin": allowedOrigin,
      },
    });
  } catch (e) {
    return new Response(JSON.stringify({ error: "Server error", details: String(e) }), {
      status: 500,
      headers: {
        "Content-Type": "application/json",
        "Access-Control-Allow-Origin": allowedOrigin,
      },
    });
  }
};
