import { serve } from "https://deno.land/std@0.168.0/http/server.ts";
import { createClient } from "https://esm.sh/@supabase/supabase-js@2";

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

    const { request_id, action } = await req.json();

    if (!request_id || !action || !["APPROVE", "REJECT"].includes(action)) {
      return new Response(
        JSON.stringify({
          error: "Invalid request. Must provide request_id and action ('APPROVE' or 'REJECT')",
        }),
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

    // 2. Fetch pending request belonging to the authenticated user
    const { data: requestRecord, error: reqError } = await adminClient
      .from("re_enrollment_requests")
      .select("*")
      .eq("id", request_id)
      .eq("user_id", user.id)
      .eq("status", "PENDING")
      .single();

    if (reqError || !requestRecord) {
      return new Response(
        JSON.stringify({ error: "Pending re-enrollment request not found or unauthorized" }),
        {
          status: 404,
          headers: { ...corsHeaders, "Content-Type": "application/json" },
        }
      );
    }

    if (action === "APPROVE") {
      // 3. Promote device state atomically
      const { data: promoteSuccess, error: promoteError } = await adminClient.rpc(
        "promote_device_state_atomic",
        {
          p_device_id: requestRecord.device_id,
          p_new_graph_hash: requestRecord.new_graph_hash,
          p_new_state_hash: requestRecord.new_state_hash,
          p_new_graph_version: requestRecord.new_graph_version,
          p_new_graph_json: requestRecord.new_graph_json,
          p_risk_level: requestRecord.risk_level,
        }
      );

      if (promoteError || !promoteSuccess) {
        return new Response(
          JSON.stringify({
            error: "Failed to promote device state",
            details: promoteError?.message,
          }),
          {
            status: 409,
            headers: { ...corsHeaders, "Content-Type": "application/json" },
          }
        );
      }

      // Update request status
      await adminClient
        .from("re_enrollment_requests")
        .update({ status: "APPROVED", reviewed_at: new Date().toISOString() })
        .eq("id", request_id);

      // Record audit event
      await adminClient.from("device_events").insert({
        device_id: requestRecord.device_id,
        event_type: "REENROLL_USER_APPROVED",
        event_version: 1,
        metadata: {
          request_id,
          new_state_hash: requestRecord.new_state_hash,
          new_graph_version: requestRecord.new_graph_version,
          timestamp: new Date().toISOString(),
        },
      });

      return new Response(
        JSON.stringify({
          success: true,
          status: "APPROVED",
          message: "Re-enrollment request approved and device state promoted to ACTIVE.",
        }),
        {
          status: 200,
          headers: { ...corsHeaders, "Content-Type": "application/json" },
        }
      );
    } else {
      // REJECT
      await adminClient
        .from("re_enrollment_requests")
        .update({ status: "REJECTED", reviewed_at: new Date().toISOString() })
        .eq("id", request_id);

      // Record audit event
      await adminClient.from("device_events").insert({
        device_id: requestRecord.device_id,
        event_type: "REENROLL_USER_REJECTED",
        event_version: 1,
        metadata: {
          request_id,
          timestamp: new Date().toISOString(),
        },
      });

      return new Response(
        JSON.stringify({
          success: true,
          status: "REJECTED",
          message: "Re-enrollment request rejected by user.",
        }),
        {
          status: 200,
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
