/**
 * Global Settings → Tunneling (FU-27). A tunnel runs in the person's own Kali sandbox and needs two
 * switches: the person's own tunnel on here, and the project's Tunnel Provider. It reaches port 4444
 * inside the sandbox, while a pool port is reached directly; the act_as sandbox never uses one.
 */
export const TUNNEL_BOTH_SWITCHES =
  "A chat uses a tunnel only when your own tunnel is on here AND the project's Tunnel Provider (Payload Direction, in the project settings) names it."
export const TUNNEL_REACHES =
  "Your tunnel runs in your own Kali sandbox and reaches port 4444 inside it; your sandbox's port from the operator's port pool, when it has one, is reached directly, without a tunnel."
// Under act-as the page offers no tunnel control: the row is the member's, and an off from it would
// end the member's own shells; the act_as sandbox never uses a tunnel.
export const TUNNEL_NEVER_ACTING_AS =
  'While you act as another person, that work runs in a separate act-as sandbox that never uses a tunnel, and this page neither turns their own tunnel on nor off.'

export const TUNNEL_SECTION_HINT_MANAGE = [
  'Configure reverse shell tunneling with your own ngrok or chisel credentials.',
  TUNNEL_BOTH_SWITCHES,
  TUNNEL_REACHES,
  'It is turned off whenever your sandbox restarts (a sandbox stops after a while unused) - turn it on again each time.',
  TUNNEL_NEVER_ACTING_AS,
  'It exposes an internet-reachable listener, breaking the LAN-only posture.',
].join(' ')

export const TUNNEL_SECTION_HINT_READ = [
  "Reverse shell tunneling runs in each person's own Kali sandbox, with their own credentials.",
  TUNNEL_BOTH_SWITCHES,
  TUNNEL_NEVER_ACTING_AS,
].join(' ')

export const TUNNEL_ENABLE_HINT =
  'When off, saved credentials are stored but no tunnel is started. Enabling starts your Kali sandbox if needed and exposes port 4444 inside it (its reverse-shell handler) to the internet via ngrok or chisel.'
export const NGROK_TOKEN_HINT =
  'Enables an ngrok TCP tunnel to port 4444 inside your Kali sandbox (the reverse-shell handler). Stageless payloads only.'
export const CHISEL_FORWARDS = 'Tunnels port 4444 inside your Kali sandbox (the reverse-shell handler) only.'
