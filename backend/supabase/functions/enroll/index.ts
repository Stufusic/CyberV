import { serve } from "https://deno.land/std@0.168.0/http/server.ts";
import { createClient } from "https://esm.sh/@supabase/supabase-js@2";
import {
  buildEnrollmentSignaturePayload,
  verifyEd25519ChallengeSignature,
} from "../_shared/crypto.ts";

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
      public_key,
      current_graph_hash,
      current_state_hash,
      current_graph_version = 1,
      canonical_graph_json,
      signature_hex,
    } = await req.json();

    if (
      !device_id ||
      !public_key ||
      !current_graph_hash ||
      !current_state_hash ||
      !canonical_graph_json ||
      !signature_hex
    ) {
      return new Response(
        JSON.stringify({ error: "Missing required device enrollment fields" }),
        {
          status: 400,
          headers: { ...corsHeaders, "Content-Type": "application/json" },
        }
      );
    }

    // 2. Verify Ed25519 enrollment signature
    const signaturePayload = buildEnrollmentSignaturePayload(
      device_id,
      public_key,
      current_graph_hash,
      current_state_hash,
      current_graph_version
    );

    const isSigValid = await verifyEd25519ChallengeSignature(
      public_key,
      signaturePayload,
      signature_hex
    );

    if (!isSigValid) {
      return new Response(
        JSON.stringify({ error: "Cryptographic enrollment signature verification failed" }),
        {
          status: 401,
          headers: { ...corsHeaders, "Content-Type": "application/json" },
        }
      );
    }

    const adminClient = createClient(
      Deno.env.get("SUPABASE_URL") ?? "",
      Deno.env.get("SUPABASE_SERVICE_ROLE_KEY") ?? ""
    );

    // 3. Check if device_id already enrolled
    const { data: existingDevice } = await adminClient
      .from("devices")
      .select("id")
      .eq("device_id", device_id)
      .maybeSingle();

    if (existingDevice) {
      return new Response(
        JSON.stringify({ error: "Device with this ID is already enrolled" }),
        {
          status: 409,
          headers: { ...corsHeaders, "Content-Type": "application/json" },
        }
      );
    }

    const graphJson =
      typeof canonical_graph_json === "string"
        ? JSON.parse(canonical_graph_json)
        : canonical_graph_json;

    // 4. Insert into devices table
    const { error: devInsertError } = await adminClient.from("devices").insert({
      user_id: user.id,
      device_id,
      public_key,
      current_graph_hash,
      current_state_hash,
      current_graph_version,
      status: "ACTIVE",
      risk_level: "LOW",
    });

    if (devInsertError) {
      return new Response(
        JSON.stringify({
          error: "Failed to create device record",
          details: devInsertError.message,
        }),
        {
          status: 500,
          headers: { ...corsHeaders, "Content-Type": "application/json" },
        }
      );
    }

    // 5. Insert initial graph into device_graphs
    const { error: graphInsertError } = await adminClient.from("device_graphs").insert({
      device_id,
      graph_version: current_graph_version,
      graph_hash: current_graph_hash,
      canonical_graph_json: graphJson,
    });

    if (graphInsertError) {
      // Rollback device if graph insert failed
      await adminClient.from("devices").delete().eq("device_id", device_id);
      return new Response(
        JSON.stringify({
          error: "Failed to persist initial evidence graph",
          details: graphInsertError.message,
        }),
        {
          status: 500,
          headers: { ...corsHeaders, "Content-Type": "application/json" },
        }
      );
    }

    // 6. Record audit event
    await adminClient.from("device_events").insert({
      device_id,
      event_type: "DEVICE_ENROLLED",
      event_version: 1,
      metadata: {
        user_id: user.id,
        current_state_hash,
        current_graph_hash,
        timestamp: new Date().toISOString(),
      },
    });

    return new Response(
      JSON.stringify({
        status: "ACTIVE",
        device_id,
        graph_version: current_graph_version,
        message: "Device successfully enrolled and bound to user account.",
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
