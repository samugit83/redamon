// L-1: uploaded alone to a partial JS Recon run (no URL, no graph target). It
// holds no secret and no endpoint, only a DOM sink and a scoped import.
import { Banner } from "@example-internal/ui";
const el = document.getElementById("banner");
el.innerHTML = location.hash;
Banner.mount(el);
