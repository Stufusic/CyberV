import { serve } from "https://deno.land/std@0.168.0/http/server.ts";
import { createClient } from "https://esm.sh/@supabase/supabase-js@2";
import {
  buildChallengeSignaturePayload,
  verifyEd25519ChallengeSignature,
} from "../_shared/crypto.ts";
import { PURPOSE_DEVICE_AUTH } from "../_shared/protocol.ts";

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

    const {
      challenge_id,
      nonce,
      device_id,
      purpose = PURPOSE_DEVICE_AUTH,
      state_hash,
      graph_version,
      signature_hex,
    } = await req.json();

    if (!challenge_id || !nonce || !device_id || !state_hash || !signature_hex) {
      return new Response(JSON.stringify({ error: "Missing required challenge proof fields" }), {
        status: 400,
        headers: { ...corsHeaders, "Content-Type": "application/json" },
      });
    }

    const adminClient = createClient(
      Deno.env.get("SUPABASE_URL") ?? "",
      Deno.env.get("SUPABASE_SERVICE_ROLE_KEY") ?? ""
    );

    // 2. Fetch device record
    const { data: device, error: devError } = await adminClient
      .from("devices")
      .select("id, public_key, current_state_hash, current_graph_version, status")
      .eq("device_id", device_id)
      .eq("user_id", user.id)
      .single();

    if (devError || !device || device.status !== "ACTIVE") {
      return new Response(JSON.stringify({ error: "Device not found or not active" }), {
        status: 403,
        headers: { ...corsHeaders, "Content-Type": "application/json" },
      });
    }

    // 3. Fetch challenge record
    const { data: chal, error: chalError } = await adminClient
      .from("challenges")
      .select("id, nonce, consumed, expires_at, device_id")
      .eq("id", challenge_id)
      .eq("device_id", device_id)
      .single();

    if (chalError || !chal) {
      return new Response(JSON.stringify({ error: "Challenge not found" }), {
        status: 404,
        headers: { ...corsHeaders, "Content-Type": "application/json" },
      });
    }

    if (chal.consumed) {
      return new Response(JSON.stringify({ error: "Challenge already consumed (replay detected)" }), {
        status: 409,
        headers: { ...corsHeaders, "Content-Type": "application/json" },
      });
    }

    if (new Date(chal.expires_at) < new Date()) {
      return new Response(JSON.stringify({ error: "Challenge expired" }), {
        status: 410,
        headers: { ...corsHeaders, "Content-Type": "application/json" },
      });
    }

    if (chal.nonce !== nonce) {
      return new Response(JSON.stringify({ error: "Nonce mismatch" }), {
        status: 400,
        headers: { ...corsHeaders, "Content-Type": "application/json" },
      });
    }

    // 4. Verify Ed25519 signature BEFORE consuming challenge (rv4.md #14)
    const payload = buildChallengeSignaturePayload(
      purpose,
      challenge_id,
      nonce,
      device_id,
      state_hash,
      graph_version
    );

    const isSigValid = await verifyEd25519ChallengeSignature(
      device.public_key,
      payload,
      signature_hex
    );

    if (!isSigValid) {
      // Do not consume challenge on invalid signature to avoid challenge-burning denial of service
      return new Response(JSON.stringify({ error: "Cryptographic signature verification failed" }), {
        status: 401,
        headers: { ...corsHeaders, "Content-Type": "application/json" },
      });
    }

    // 5. Atomically consume challenge via SQL function
    const { data: consumeSuccess, error: consumeError } = await adminClient.rpc(
      "consume_challenge_atomic",
      { p_challenge_id: challenge_id, p_nonce: nonce }
    );

    if (consumeError || !consumeSuccess) {
      return new Response(JSON.stringify({ error: "Challenge consumption failed" }), {
        status: 409,
        headers: { ...corsHeaders, "Content-Type": "application/json" },
      });
    }

    // 6. Check state hash against database (rv4.md #11)
    const isStateMatch = device.current_state_hash === state_hash;

    // 7. Record audit event
    await adminClient.from("device_events").insert({
      device_id,
      event_type: isStateMatch ? "AUTH_SUCCESS" : "AUTH_STATE_MUTATION",
      event_version: 1,
      metadata: {
        purpose,
        presented_state_hash: state_hash,
        expected_state_hash: device.current_state_hash,
        graph_version,
        is_state_match: isStateMatch,
        timestamp: new Date().toISOString(),
      },
    });

    if (!isStateMatch) {
      return new Response(
        JSON.stringify({
          authenticated: true,
          status: "STATE_MUTATION_DETECTED",
          message: "Device authenticated via Ed25519, but hardware state has mutated. Re-enrollment or policy review required.",
          expected_state_hash: device.current_state_hash,
          presented_state_hash: state_hash,
        }),
        {
          status: 200,
          headers: { ...corsHeaders, "Content-Type": "application/json" },
        }
      );
    }

    // Update last_seen_at
    await adminClient
      .from("devices")
      .update({ last_seen_at: new Date().toISOString() })
      .eq("device_id", device_id);

    return new Response(
      JSON.stringify({
        authenticated: true,
        status: "AUTHENTICATED",
        device_id,
        state_hash,
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
