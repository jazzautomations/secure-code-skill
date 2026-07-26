import { createClient } from "@supabase/supabase-js";
const admin = createClient(url, Deno.env.get("SERVICE_ROLE_KEY")); // server-side, ok
