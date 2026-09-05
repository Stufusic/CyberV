import { serve } from "https://deno.land/std@0.168.0/http/server.ts";
import { createClient } from "https://esm.sh/@supabase/supabase-js@2";
import {
  buildKeyRotationSignaturePayload,
  verifyEd25519KeyRotationSignatures,
} from "../_shared/crypto.ts";
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

    // 1. Authenticate user session
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

    const {
      device_id,
      old_public_key,
      new_public_key,
      state_hash,
      graph_version,
      nonce,
      timestamp,
      signature_old,
      signature_new,
    } = await req.json();

    if (
      !device_id ||
      !old_public_key ||
      !new_public_key ||
      !state_hash ||
      graph_version === undefined ||
      !nonce ||
      timestamp === undefined ||
      !signature_old ||
      !signature_new
    ) {
      return new Response(
        JSON.stringify({ error: "Missing required key rotation fields" }),
        {
          status: 400,
          headers: { ...corsHeaders, "Content-Type": "application/json" },
        }
      );
    }

    if (old_public_key.toLowerCase() === new_public_key.toLowerCase()) {
      return new Response(
        JSON.stringify({ error: "New public key cannot be identical to current public key" }),
        {
          status: 400,
          headers: { ...corsHeaders, "Content-Type": "application/json" },
        }
      );
    }

    // 2. Anti-DoS Rate Limiting: Max 3 key rotations per 10 minutes per device
    const rateCheck = checkRateLimit(`rotate:${device_id}`, 3, 600);
    if (!rateCheck.allowed) {
      return new Response(
        JSON.stringify({
          error: "Too many key rotation requests. Please wait before rotating key again.",
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

    const adminClient = createClient(
      Deno.env.get("SUPABASE_URL") ?? "",
      Deno.env.get("SUPABASE_SERVICE_ROLE_KEY") ?? ""
    );

    // 3. Fetch device record
    const { data: device, error: devError } = await adminClient
      .from("devices")
      .select("id, user_id, public_key, current_state_hash, current_graph_version, status")
      .eq("device_id", device_id)
      .single();

    if (devError || !device) {
      return new Response(JSON.stringify({ error: "Device not found" }), {
        status: 404,
        headers: { ...corsHeaders, "Content-Type": "application/json" },
      });
    }

    if (device.user_id !== user.id) {
      return new Response(JSON.stringify({ error: "Forbidden: You do not own this device" }), {
        status: 403,
        headers: { ...corsHeaders, "Content-Type": "application/json" },
      });
    }

    if (device.status === "REVOKED") {
      return new Response(
        JSON.stringify({
          error: "Forbidden: Device has been permanently revoked and cannot rotate keys.",
          status: "REVOKED",
        }),
        {
          status: 403,
          headers: { ...corsHeaders, "Content-Type": "application/json" },
        }
      );
    }

    if (device.status !== "ACTIVE") {
      return new Response(
        JSON.stringify({
          error: `Cannot rotate key: Device status is ${device.status} (must be ACTIVE)`,
          status: device.status,
        }),
        {
          status: 409,
          headers: { ...corsHeaders, "Content-Type": "application/json" },
        }
      );
    }

    // Verify key and state consistency
    if (device.public_key.toLowerCase() !== old_public_key.toLowerCase()) {
      return new Response(
        JSON.stringify({
          error: "Public key mismatch: Presented old_public_key does not match registered device key",
        }),
        {
          status: 409,
          headers: { ...corsHeaders, "Content-Type": "application/json" },
        }
      );
    }

    if (device.current_state_hash !== state_hash || device.current_graph_version !== graph_version) {
      return new Response(
        JSON.stringify({
          error: "Hardware state hash or graph version mismatch with active device state",
        }),
        {
          status: 409,
          headers: { ...corsHeaders, "Content-Type": "application/json" },
        }
      );
    }

    // 4. Fetch and consume rotation challenge Nonce
    const { data: challenge, error: chalError } = await adminClient
      .from("challenges")
      .select("id, nonce, consumed, expires_at, device_id")
      .eq("device_id", device_id)
      .eq("nonce", nonce)
      .single();

    if (chalError || !challenge) {
      return new Response(
        JSON.stringify({ error: "Challenge nonce not found for this device" }),
        {
          status: 404,
          headers: { ...corsHeaders, "Content-Type": "application/json" },
        }
      );
    }

    if (challenge.consumed) {
      return new Response(
        JSON.stringify({ error: "Challenge nonce already consumed (replay attack detected)" }),
        {
          status: 409,
          headers: { ...corsHeaders, "Content-Type": "application/json" },
        }
      );
    }

    const now = new Date();
    if (new Date(challenge.expires_at) < now) {
      return new Response(
        JSON.stringify({ error: "Challenge nonce has expired" }),
        {
          status: 410,
          headers: { ...corsHeaders, "Content-Type": "application/json" },
        }
      );
    }

    // Consume challenge nonce immediately
    await adminClient
      .from("challenges")
      .update({ consumed: true, consumed_at: now.toISOString() })
      .eq("id", challenge.id);

    // 5. Verify Dual Signatures (Dual Proof-of-Possession)
    const payload = buildKeyRotationSignaturePayload(
      device_id,
      old_public_key,
      new_public_key,
      state_hash,
      graph_version,
      nonce,
      timestamp,
    );

    const isDualSignatureValid = await verifyEd25519KeyRotationSignatures(
      old_public_key,
      new_public_key,
      payload,
      signature_old,
      signature_new,
    );

    if (!isDualSignatureValid) {
      return new Response(
        JSON.stringify({
          error: "Dual signature verification failed. Both old and new private key signatures must be valid.",
        }),
        {
          status: 400,
          headers: { ...corsHeaders, "Content-Type": "application/json" },
        }
      );
    }

    // 6. Atomically update device public key
    const { error: updateError } = await adminClient
      .from("devices")
      .update({
        public_key: new_public_key.toLowerCase(),
        updated_at: now.toISOString(),
      })
      .eq("device_id", device_id);

    if (updateError) {
      return new Response(
        JSON.stringify({ error: "Failed to update device public key", details: updateError.message }),
        {
          status: 500,
          headers: { ...corsHeaders, "Content-Type": "application/json" },
        }
      );
    }

    // 7. Record security audit event
    await adminClient.from("device_events").insert({
      device_id,
      event_type: "DEVICE_KEY_ROTATED",
      event_version: 1,
      metadata: {
        old_public_key: old_public_key.toLowerCase(),
        new_public_key: new_public_key.toLowerCase(),
        state_hash,
        graph_version,
        rotated_by_user_id: user.id,
        timestamp: now.toISOString(),
      },
    });

    return new Response(
      JSON.stringify({
        success: true,
        status: "ACTIVE",
        new_public_key: new_public_key.toLowerCase(),
        message: "Device identity signing key rotated successfully.",
      }),
      {
        status: 200,
        headers: {
          ...corsHeaders,
          ...rateLimitHeaders(rateCheck),
          "Content-Type": "application/json",
        },
      }
    );
  } catch (err: unknown) {
    const message = err instanceof Error ? err.message : String(err);
    return new Response(
      JSON.stringify({ error: "Internal server error", details: message }),
      {
        status: 500,
        headers: { ...corsHeaders, "Content-Type": "application/json" },
      }
    );
  }
});
