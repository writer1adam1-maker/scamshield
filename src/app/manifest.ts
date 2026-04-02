import type { MetadataRoute } from "next";

export default function manifest(): MetadataRoute.Manifest {
  return {
    name: "ScamShieldy",
    short_name: "ScamShieldy",
    description: "Is This Legit or Am I About to Get Screwed?",
    theme_color: "#0a0a0f",
    background_color: "#0a0a0f",
    display: "standalone",
    start_url: "/",
    scope: "/",
    icons: [
      {
        src: "/icons/icon-192.png",
        sizes: "192x192",
        type: "image/png",
      },
      {
        src: "/icons/icon-512.png",
        sizes: "512x512",
        type: "image/png",
      },
    ],
  };
}
