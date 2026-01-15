export default async (request, context) => {
  // Basic CORS. Replace with your real domain once you confirm it works.
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

  return new Response(
    JSON.stringify({ answer: "Hello from ben-chat. Your function is live." }),
    {
      status: 200,
      headers: {
        "Content-Type": "application/json",
        "Access-Control-Allow-Origin": allowedOrigin,
      },
    }
  );
};
