import { serve } from "https://deno.land/std@0.168.0/http/server.ts";
import { createClient } from "https://esm.sh/@supabase/supabase-js@2";
import { CHALLENGE_TTL_SECONDS, PURPOSE_DEVICE_AUTH } from "../_shared/protocol.ts";
import { bufferToHex } from "../_shared/component_hasher.ts";
import { checkRateLimit, rateLimitHeaders } from "../_shared/rate_limiter.ts";

const corsHeaders = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Headers": "authorization, x-client-info, apikey, content-type",
};

serve(async (req) => {
  if (req.method === "OPTIONS") {
    return new Response("ok", { headers: corsHeaders });
  }

  try {
    const supabaseClient = createClient(
      Deno.env.get("SUPABASE_URL") ?? "",
      Deno.env.get("SUPABASE_ANON_KEY") ?? "",
      {
        global: {
          headers: { Authorization: req.headers.get("Authorization")! },
        },
      }
    );

    // 1. Authenticate user
    const {
      data: { user },
      error: userError,
    } = await supabaseClient.auth.getUser();

    if (userError || !user) {
      return new Response(JSON.stringify({ error: "Unauthorized user session" }), {
        status: 401,
        headers: { ...corsHeaders, "Content-Type": "application/json" },
      });
    }

    const { device_id, purpose = PURPOSE_DEVICE_AUTH } = await req.json();

    if (!device_id) {
      return new Response(JSON.stringify({ error: "device_id is required" }), {
        status: 400,
        headers: { ...corsHeaders, "Content-Type": "application/json" },
      });
    }

    const rateCheck = checkRateLimit(`challenge:${device_id}`, 30, 60);
    if (!rateCheck.allowed) {
      return new Response(
        JSON.stringify({
          error: "Rate limit exceeded for challenge generation",
          retry_after: rateCheck.retryAfterSeconds,
        }),
        {
          status: 429,
          headers: {
            ...corsHeaders,
            ...rateLimitHeaders(rateCheck),
            "Content-Type": "application/json",
          },
        }
      );
    }

    // 2. Verify device exists and is active for this user
    const { data: device, error: devError } = await supabaseClient
      .from("devices")
      .select("id, status")
      .eq("device_id", device_id)
      .eq("user_id", user.id)
      .single();

    if (devError || !device || device.status !== "ACTIVE") {
      return new Response(JSON.stringify({ error: "Device not found or not active" }), {
        status: 403,
        headers: { ...corsHeaders, "Content-Type": "application/json" },
      });
    }

    // 3. Generate 256-bit CSPRNG nonce
    const nonceBytes = new Uint8Array(32);
    crypto.getRandomValues(nonceBytes);
    const nonce = bufferToHex(nonceBytes);

    const now = new Date();
    const expiresAt = new Date(now.getTime() + CHALLENGE_TTL_SECONDS * 1000);

    // 4. Insert challenge using service role or elevated client
    const adminClient = createClient(
      Deno.env.get("SUPABASE_URL") ?? "",
      Deno.env.get("SUPABASE_SERVICE_ROLE_KEY") ?? ""
    );

    const { data: challenge, error: insertError } = await adminClient
      .from("challenges")
      .insert({
        device_id,
        nonce,
        consumed: false,
        issued_at: now.toISOString(),
        expires_at: expiresAt.toISOString(),
      })
      .select("id")
      .single();

    if (insertError || !challenge) {
      return new Response(JSON.stringify({ error: "Failed to generate challenge" }), {
        status: 500,
        headers: { ...corsHeaders, "Content-Type": "application/json" },
      });
    }

    return new Response(
      JSON.stringify({
        challenge_id: challenge.id,
        nonce,
        device_id,
        purpose,
        issued_at: Math.floor(now.getTime() / 1000),
        expires_at: Math.floor(expiresAt.getTime() / 1000),
      }),
      {
        status: 200,
        headers: { ...corsHeaders, "Content-Type": "application/json" },
      }
    );
  } catch (err: any) {
    return new Response(JSON.stringify({ error: err.message }), {
      status: 500,
      headers: { ...corsHeaders, "Content-Type": "application/json" },
    });
  }
});
