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

    const { device_id, reason } = await req.json();

    if (!device_id || typeof device_id !== "string") {
      return new Response(
        JSON.stringify({
          error: "Invalid request. 'device_id' string is required.",
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

    // 2. Fetch device and verify user ownership
    const { data: device, error: fetchError } = await adminClient
      .from("devices")
      .select("id, device_id, user_id, status")
      .eq("device_id", device_id)
      .single();

    if (fetchError || !device) {
      return new Response(
        JSON.stringify({ error: "Device not found" }),
        {
          status: 404,
          headers: { ...corsHeaders, "Content-Type": "application/json" },
        }
      );
    }

    if (device.user_id !== user.id) {
      return new Response(
        JSON.stringify({ error: "Forbidden: You do not own this device" }),
        {
          status: 403,
          headers: { ...corsHeaders, "Content-Type": "application/json" },
        }
      );
    }

    if (device.status === "REVOKED") {
      return new Response(
        JSON.stringify({
          error: "Device is already revoked",
          status: "REVOKED",
        }),
        {
          status: 400,
          headers: { ...corsHeaders, "Content-Type": "application/json" },
        }
      );
    }

    // 3. Atomically revoke device status
    const { error: updateError } = await adminClient
      .from("devices")
      .update({
        status: "REVOKED",
        updated_at: new Date().toISOString(),
      })
      .eq("device_id", device_id);

    if (updateError) {
      return new Response(
        JSON.stringify({ error: "Failed to update device status", details: updateError.message }),
        {
          status: 500,
          headers: { ...corsHeaders, "Content-Type": "application/json" },
        }
      );
    }

    // 4. Invalidate any open challenges for this device to prevent further attestations
    await adminClient
      .from("challenges")
      .update({ consumed: true, consumed_at: new Date().toISOString() })
      .eq("device_id", device_id)
      .eq("consumed", false);

    // 5. Record security audit event in device_events
    await adminClient.from("device_events").insert({
      device_id,
      event_type: "DEVICE_REVOKED",
      event_version: 1,
      metadata: {
        revoked_by_user_id: user.id,
        reason: reason || "User initiated immediate device revocation via Dashboard",
        revoked_at: new Date().toISOString(),
      },
    });

    return new Response(
      JSON.stringify({
        success: true,
        device_id,
        status: "REVOKED",
        message: "Device credentials revoked immediately. All further attestation nonces invalidated.",
      }),
      {
        status: 200,
        headers: { ...corsHeaders, "Content-Type": "application/json" },
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
