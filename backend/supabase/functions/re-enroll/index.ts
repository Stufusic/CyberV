import { serve } from "https://deno.land/std@0.168.0/http/server.ts";
import { createClient } from "https://esm.sh/@supabase/supabase-js@2";
import {
  buildReenrollmentSignaturePayload,
  verifyEd25519ChallengeSignature,
} from "../_shared/crypto.ts";
import { evaluateRisk, PolicyDecision } from "../_shared/risk.ts";

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
      previous_state_hash,
      new_state_hash,
      new_graph_hash,
      new_graph_version,
      new_graph_json,
      changes = [],
      has_partial_status = false,
      reason = "Hardware Re-enrollment",
      signature_hex,
    } = await req.json();

    if (
      !device_id ||
      !previous_state_hash ||
      !new_state_hash ||
      !new_graph_hash ||
      new_graph_version === undefined ||
      !new_graph_json ||
      !signature_hex
    ) {
      return new Response(
        JSON.stringify({ error: "Missing required re-enrollment fields" }),
        {
          status: 400,
          headers: { ...corsHeaders, "Content-Type": "application/json" },
        }
      );
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

    if (devError || !device) {
      return new Response(JSON.stringify({ error: "Device not found or not owned by user" }), {
        status: 404,
        headers: { ...corsHeaders, "Content-Type": "application/json" },
      });
    }

    if (device.status === "REVOKED") {
      return new Response(
        JSON.stringify({
          error: "Forbidden: Device has been permanently revoked and cannot submit re-enrollment.",
          status: "REVOKED",
        }),
        {
          status: 403,
          headers: { ...corsHeaders, "Content-Type": "application/json" },
        }
      );
    }

    // Check previous state hash consistency
    if (device.current_state_hash !== previous_state_hash) {
      return new Response(
        JSON.stringify({
          error: "Previous state hash mismatch with current device state",
          expected: device.current_state_hash,
          received: previous_state_hash,
        }),
        {
          status: 409,
          headers: { ...corsHeaders, "Content-Type": "application/json" },
        }
      );
    }

    // 3. Verify Re-enrollment Ed25519 signature
    const signaturePayload = buildReenrollmentSignaturePayload(
      device_id,
      previous_state_hash,
      new_state_hash,
      new_graph_hash,
      new_graph_version,
      reason
    );

    const isSigValid = await verifyEd25519ChallengeSignature(
      device.public_key,
      signaturePayload,
      signature_hex
    );

    if (!isSigValid) {
      return new Response(
        JSON.stringify({ error: "Cryptographic re-enrollment signature verification failed" }),
        {
          status: 401,
          headers: { ...corsHeaders, "Content-Type": "application/json" },
        }
      );
    }

    // 4. Evaluate risk assessment
    const assessment = evaluateRisk(
      device.current_graph_version,
      new_graph_version,
      changes,
      has_partial_status
    );

    // 5. Handle Policy Decisions
    if (assessment.decision === PolicyDecision.AutoPromote || assessment.decision === PolicyDecision.Trusted) {
      // Atomic state promotion
      const { data: promoteSuccess, error: promoteError } = await adminClient.rpc(
        "promote_device_state_atomic",
        {
          p_device_id: device_id,
          p_new_graph_hash: new_graph_hash,
          p_new_state_hash: new_state_hash,
          p_new_graph_version: new_graph_version,
          p_new_graph_json: typeof new_graph_json === "string" ? JSON.parse(new_graph_json) : new_graph_json,
          p_risk_level: assessment.level,
        }
      );

      if (promoteError || !promoteSuccess) {
        return new Response(
          JSON.stringify({
            error: "State promotion failed",
            details: promoteError?.message,
          }),
          {
            status: 409,
            headers: { ...corsHeaders, "Content-Type": "application/json" },
          }
        );
      }

      // Record audit event
      await adminClient.from("device_events").insert({
        device_id,
        event_type: "REENROLL_AUTO_PROMOTED",
        event_version: 1,
        metadata: {
          previous_state_hash,
          new_state_hash,
          new_graph_version,
          risk_assessment: assessment,
          timestamp: new Date().toISOString(),
        },
      });

      return new Response(
        JSON.stringify({
          status: "ACTIVE",
          decision: assessment.decision,
          risk_assessment: assessment,
          message: "Device state automatically promoted.",
        }),
        {
          status: 200,
          headers: { ...corsHeaders, "Content-Type": "application/json" },
        }
      );
    } else if (assessment.decision === PolicyDecision.RequiresUserApproval) {
      // Insert into re_enrollment_requests
      const { data: requestRecord, error: insertError } = await adminClient
        .from("re_enrollment_requests")
        .insert({
          device_id,
          user_id: user.id,
          previous_state_hash,
          new_state_hash,
          new_graph_hash,
          new_graph_version,
          new_graph_json: typeof new_graph_json === "string" ? JSON.parse(new_graph_json) : new_graph_json,
          risk_score: assessment.score,
          risk_level: assessment.level,
          decision: assessment.decision,
          reason,
          proof_signature: signature_hex,
          status: "PENDING",
        })
        .select("id")
        .single();

      if (insertError) {
        return new Response(
          JSON.stringify({
            error: "Failed to create re-enrollment request",
            details: insertError.message,
          }),
          {
            status: 500,
            headers: { ...corsHeaders, "Content-Type": "application/json" },
          }
        );
      }

      // Update device status to PENDING
      await adminClient
        .from("devices")
        .update({ status: "PENDING", updated_at: new Date().toISOString() })
        .eq("device_id", device_id);

      // Record audit event
      await adminClient.from("device_events").insert({
        device_id,
        event_type: "REENROLL_PENDING_APPROVAL",
        event_version: 1,
        metadata: {
          request_id: requestRecord?.id,
          previous_state_hash,
          new_state_hash,
          new_graph_version,
          risk_assessment: assessment,
          timestamp: new Date().toISOString(),
        },
      });

      return new Response(
        JSON.stringify({
          status: "PENDING_APPROVAL",
          request_id: requestRecord?.id,
          decision: assessment.decision,
          risk_assessment: assessment,
          message: "Hardware mutation requires explicit user confirmation.",
        }),
        {
          status: 202,
          headers: { ...corsHeaders, "Content-Type": "application/json" },
        }
      );
    } else {
      // REJECTED
      await adminClient.from("device_events").insert({
        device_id,
        event_type: "REENROLL_REJECTED",
        event_version: 1,
        metadata: {
          previous_state_hash,
          new_state_hash,
          new_graph_version,
          risk_assessment: assessment,
          timestamp: new Date().toISOString(),
        },
      });

      return new Response(
        JSON.stringify({
          status: "REJECTED",
          decision: assessment.decision,
          risk_assessment: assessment,
          error: "Re-enrollment rejected by risk security policy.",
        }),
        {
          status: 403,
          headers: { ...corsHeaders, "Content-Type": "application/json" },
        }
      );
    }
  } catch (err: any) {
    return new Response(JSON.stringify({ error: err.message }), {
      status: 500,
      headers: { ...corsHeaders, "Content-Type": "application/json" },
    });
  }
});
